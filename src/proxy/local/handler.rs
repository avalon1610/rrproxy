use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming, Request, Response};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use super::chunking::{chunk_and_send_request, forward_single_request, handle_connect_request};
use super::config::LocalProxyConfig;
use super::dynamic_tls::DynamicTlsHandler;
use crate::cert_gen::{self, CertConfig, CertGenerationMode, RootCaConfig};
use crate::utils::stream::ReconstructedStream;

pub async fn start(config: LocalProxyConfig) -> Result<()> {
    // Handle certificate generation or validation
    handle_certificates(&config)?;

    let listen_addr: SocketAddr = config.listen_addr.parse()?;
    let listener = TcpListener::bind(listen_addr).await?;
    info!("Local proxy listening on {}", listen_addr);

    // Create dynamic TLS handler for HTTPS interception
    let tls_handler = Arc::new(DynamicTlsHandler::new(&config)?);
    let config = Arc::new(config);

    loop {
        let (stream, _) = listener.accept().await?;
        let config = Arc::clone(&config);
        let tls_handler = Arc::clone(&tls_handler);

        tokio::task::spawn(async move {
            if let Err(err) = handle_raw_connection(stream, config, tls_handler).await {
                warn!("Error handling connection: {:?}", err);
            }
        });
    }
}

async fn handle_raw_connection(
    mut stream: TcpStream,
    config: Arc<LocalProxyConfig>,
    tls_handler: Arc<DynamicTlsHandler>,
) -> Result<()> {
    // Read enough data to determine if it's a CONNECT request
    let mut buffer = vec![0u8; 1024];
    let n = stream.read(&mut buffer).await?;

    if n == 0 {
        return Ok(());
    }

    let request_data = String::from_utf8_lossy(&buffer[..n]);

    if request_data.starts_with("CONNECT ") {
        // Handle CONNECT request using dynamic TLS handler
        info!("Handling CONNECT request with dynamic TLS");
        tls_handler
            .handle_connect_request(stream, request_data.to_string(), config)
            .await
    } else {
        // Handle HTTP request - reconstruct the stream and use hyper
        let reconstructed_stream = ReconstructedStream::new(buffer[..n].to_vec(), stream);
        let io = TokioIo::new(reconstructed_stream);

        if let Err(err) = http1::Builder::new()
            .serve_connection(
                io,
                service_fn(move |req| handle_http_request(req, Arc::clone(&config))),
            )
            .await
        {
            warn!("Error serving HTTP connection: {:?}", err);
        }
        Ok(())
    }
}

async fn handle_http_request(
    req: Request<Incoming>,
    config: Arc<LocalProxyConfig>,
) -> Result<Response<Full<Bytes>>> {
    let start_time = Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();

    info!(
        method = %method,
        uri = %uri,
        "Processing incoming HTTP request"
    );

    // Handle CONNECT requests for HTTPS tunneling
    if method == hyper::Method::CONNECT {
        return handle_connect_request(req, config).await;
    }

    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();

    let request_size = body_bytes.len();
    debug!(
        method = %method,
        uri = %uri,
        request_size = %request_size,
        chunk_size = %config.chunk_size,
        will_chunk = %(request_size > config.chunk_size),
        "HTTP request body collected"
    );

    let result = if body_bytes.len() > config.chunk_size {
        info!(
            method = %method,
            uri = %uri,
            request_size = %request_size,
            chunk_size = %config.chunk_size,
            "HTTP request will be chunked"
        );
        chunk_and_send_request(parts, body_bytes, config).await
    } else {
        debug!(
            method = %method,
            uri = %uri,
            request_size = %request_size,
            "HTTP request will be forwarded as single request"
        );
        forward_single_request(parts, body_bytes, config).await
    };

    let duration = start_time.elapsed();
    match &result {
        Ok(response) => {
            // Log detailed response information at debug level - we can't easily access body here without consuming it
            tracing::debug!(
                method = %method,
                uri = %uri,
                status = %response.status(),
                headers = ?response.headers(),
                "HTTP response details"
            );

            info!(
                method = %method,
                uri = %uri,
                status = %response.status(),
                duration_ms = %duration.as_millis(),
                "HTTP request completed successfully"
            );
        }
        Err(error) => {
            warn!(
                method = %method,
                uri = %uri,
                error = %error,
                duration_ms = %duration.as_millis(),
                "HTTP request failed"
            );
        }
    }

    result
}

/// Handle certificate generation and validation
fn handle_certificates(config: &LocalProxyConfig) -> Result<()> {
    if config.generate_ca {
        info!("Root CA generation requested");

        // Clean up existing certificate cache since the new CA will make them invalid
        if std::path::Path::new(&config.cert_cache_dir).exists() {
            info!("Cleaning up existing certificate cache due to new root CA generation");
            if let Err(e) = std::fs::remove_dir_all(&config.cert_cache_dir) {
                warn!("Failed to clean up certificate cache directory: {}", e);
            } else {
                info!("Certificate cache directory cleaned up successfully");
            }
        }

        // Generate Root CA
        let ca_config = CertConfig {
            common_name: config.ca_common_name.clone(),
            organization: "Local Proxy CA".to_string(),
            org_unit: "Certificate Authority".to_string(),
            validity_days: 3650, // 10 years for CA
            san_domains: vec![],
            ..Default::default()
        };

        info!("Generating Root CA: {}", ca_config.common_name);

        let root_ca_config = RootCaConfig {
            ca_cert_path: None,
            ca_key_path: None,
            ca_cert_config: ca_config,
        };

        let mode = CertGenerationMode::GenerateRootCa(root_ca_config);
        let dummy_cert_config = CertConfig::default(); // This won't be used for CA generation

        let result = cert_gen::generate_certificate_with_mode(&dummy_cert_config, &mode)?;

        // Save the CA certificate and key
        if let (Some(ca_cert), Some(ca_key)) = (&result.ca_cert_pem, &result.ca_key_pem) {
            std::fs::write(&config.ca_cert_file, ca_cert)?;
            std::fs::write(&config.ca_key_file, ca_key)?;
            info!("Root CA certificate saved to: {}", config.ca_cert_file);
            info!("Root CA private key saved to: {}", config.ca_key_file);
        } else {
            return Err(anyhow::anyhow!("Failed to generate Root CA"));
        }
    } else {
        // Validate existing CA certificates
        info!(
            "Validating existing Root CA files: {} and {}",
            config.ca_cert_file, config.ca_key_file
        );
    }

    // Create certificate cache directory
    if !std::path::Path::new(&config.cert_cache_dir).exists() {
        std::fs::create_dir_all(&config.cert_cache_dir)?;
        info!(
            "Created certificate cache directory: {}",
            config.cert_cache_dir
        );
    }

    Ok(())
}
