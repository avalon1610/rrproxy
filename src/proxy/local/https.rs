use anyhow::{anyhow, Result};
use bytes::Bytes;
use hyper::{body::Incoming, Request, Response};
use hyper_util::rt::TokioIo;
use http_body_util::{BodyExt, Full};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn, error};
use native_tls::{Identity, TlsAcceptor};
use tokio_native_tls::TlsAcceptor as TokioTlsAcceptor;
use std::fs;
use super::config::LocalProxyConfig;
use super::chunking::{chunk_and_send_request, forward_single_request};

pub fn create_tls_acceptor() -> Result<TokioTlsAcceptor> {
    // First try to use PKCS#12 file if it exists
    if std::path::Path::new("cert.p12").exists() {
        info!("Using existing PKCS#12 certificate file");
        return create_tls_acceptor_from_p12();
    }
    
    // If no PKCS#12 file exists, create one
    info!("PKCS#12 certificate not found, generating new one");
    generate_and_load_p12_certificate()
}

fn create_tls_acceptor_from_p12() -> Result<TokioTlsAcceptor> {
    let p12_data = fs::read("cert.p12")?;
    let identity = Identity::from_pkcs12(&p12_data, "")?;
    let acceptor = TlsAcceptor::new(identity)?;
    Ok(TokioTlsAcceptor::from(acceptor))
}

fn generate_and_load_p12_certificate() -> Result<TokioTlsAcceptor> {
    use crate::cert_gen::{CertConfig, generate_certificate};
    
    info!("Generating new PKCS#12 certificate for TLS");
    
    // Generate certificate
    let config = CertConfig::default();
    let (cert_pem, key_pem) = generate_certificate(&config)?;
    
    // Save PEM files for debugging
    fs::write("cert.pem", &cert_pem)?;
    fs::write("key.pem", &key_pem)?;
    
    // Create PKCS#12 using OpenSSL command if available
    let temp_combined = format!("{}\n{}", cert_pem, key_pem);
    fs::write("temp_combined.pem", &temp_combined)?;
    
    let openssl_result = std::process::Command::new("openssl")
        .args(&[
            "pkcs12", "-export",
            "-in", "temp_combined.pem", 
            "-out", "cert.p12",
            "-passout", "pass:",
            "-nodes"
        ])
        .output();
    
    // Clean up temporary file
    let _ = fs::remove_file("temp_combined.pem");
    
    match openssl_result {
        Ok(output) if output.status.success() => {
            info!("Successfully created PKCS#12 certificate using OpenSSL");
            create_tls_acceptor_from_p12()
        }
        _ => {
            warn!("OpenSSL not available, trying manual PKCS#12 creation");
            create_manual_pkcs12(&cert_pem, &key_pem)
        }
    }
}

fn create_manual_pkcs12(cert_pem: &str, key_pem: &str) -> Result<TokioTlsAcceptor> {
    // Create a simple PKCS#12 structure manually
    // This is a workaround for systems without OpenSSL
    
    // For the identity, we need to convert our PEM data to a format that native-tls accepts
    // Let's try combining them in a specific way that works with from_pkcs8
    
    // Extract the actual certificate and key data without PEM headers
    let cert_lines: Vec<&str> = cert_pem.lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let key_lines: Vec<&str> = key_pem.lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    
    let cert_b64 = cert_lines.join("");
    let key_b64 = key_lines.join("");
    
    // Try creating a combined PEM structure that native-tls might accept
    let combined_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        cert_b64, key_b64
    );
    
    // Try different approaches
    
    // Approach 1: Use the combined PEM as both cert and key for from_pkcs8
    let combined_bytes = combined_pem.as_bytes();
    if let Ok(identity) = Identity::from_pkcs8(combined_bytes, combined_bytes) {
        let acceptor = TlsAcceptor::new(identity)?;
        return Ok(TokioTlsAcceptor::from(acceptor));
    }
    
    // Approach 2: Use individual PEM files as bytes
    let cert_bytes = cert_pem.as_bytes();
    let key_bytes = key_pem.as_bytes();
    if let Ok(identity) = Identity::from_pkcs8(cert_bytes, key_bytes) {
        let acceptor = TlsAcceptor::new(identity)?;
        return Ok(TokioTlsAcceptor::from(acceptor));
    }
    
    // If all else fails, create a minimal PKCS#12 file manually
    // This is a last resort - create empty PKCS#12 and try to use it
    let minimal_p12 = create_minimal_pkcs12();
    fs::write("cert.p12", minimal_p12)?;
    
    let identity = Identity::from_pkcs12(&fs::read("cert.p12")?, "")?;
    let acceptor = TlsAcceptor::new(identity)?;
    Ok(TokioTlsAcceptor::from(acceptor))
}

fn create_minimal_pkcs12() -> Vec<u8> {
    // This is a very basic PKCS#12 structure
    // In a real implementation, you'd use a proper ASN.1 library
    // For now, return a minimal valid PKCS#12 structure
    vec![
        0x30, 0x82, 0x01, 0x00, // SEQUENCE (256 bytes)
        // This would contain the actual PKCS#12 structure
        // For now, just return an empty structure that won't work
        // but won't crash the parser
    ]
}

pub async fn handle_connect_request(
    mut client_stream: TcpStream, 
    request_data: String, 
    config: Arc<LocalProxyConfig>
) -> Result<()> {
    // Parse the CONNECT request
    let lines: Vec<&str> = request_data.lines().collect();
    if lines.is_empty() {
        return Err(anyhow!("Empty CONNECT request"));
    }
    
    let first_line = lines[0];
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(anyhow!("Invalid CONNECT request format"));
    }
    
    let target = parts[1];
    info!("CONNECT request to target: {}, will terminate TLS and extract HTTP requests", target);
    
    // If we haven't received the complete headers, read more
    if !request_data.contains("\r\n\r\n") {
        let mut additional_buffer = vec![0u8; 1024];
        let n = client_stream.read(&mut additional_buffer).await?;
        if n > 0 {
            // We can ignore the additional headers for CONNECT
        }
    }
    
    // Send 200 Connection Established to client
    let success_response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    client_stream.write_all(success_response.as_bytes()).await?;
    
    info!("Sent 200 Connection Established, client will start TLS handshake");
    
    // Create TLS acceptor with self-signed certificate
    let tls_acceptor = match create_tls_acceptor() {
        Ok(acceptor) => acceptor,
        Err(e) => {
            error!("Failed to create TLS acceptor: {}", e);
            return Err(anyhow!("Failed to create TLS acceptor: {}", e));
        }
    };
    
    // Accept TLS connection from client
    info!("Starting TLS handshake with client for target {}", target);
    let tls_stream = match tls_acceptor.accept(client_stream).await {
        Ok(stream) => stream,
        Err(e) => {
            error!("TLS handshake failed for target {}: {}", target, e);
            return Err(anyhow!("TLS handshake failed: {}", e));
        }
    };
    
    info!("TLS handshake completed, will now extract HTTP requests from target {}", target);
    
    // Now we have a TLS stream with the client. We need to:
    // 1. Read HTTP requests from the TLS stream
    // 2. Process them through our chunking logic
    // 3. Forward to remote proxy as HTTP requests with target info
    
    // Use hyper to handle HTTP over the TLS stream
    let io = TokioIo::new(tls_stream);
    let target_for_service = target.to_string();
    let config_for_service = Arc::clone(&config);
    
    if let Err(err) = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, hyper::service::service_fn(move |req| {
            handle_https_request(req, target_for_service.clone(), Arc::clone(&config_for_service))
        }))
        .await
    {
        warn!("Error serving HTTPS connection for {}: {:?}", target, err);
    }
    
    info!("HTTPS connection completed for target {}", target);
    Ok(())
}

pub async fn handle_https_request(
    mut req: Request<Incoming>,
    target_host: String,
    config: Arc<LocalProxyConfig>,
) -> Result<Response<Full<Bytes>>> {
    let start_time = Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    
    // Construct the full HTTPS URL by combining target host with request URI
    let full_url = if uri.to_string().starts_with("/") {
        format!("https://{}{}", target_host, uri)
    } else {
        format!("https://{}/{}", target_host, uri.to_string().trim_start_matches('/'))
    };
    
    info!(
        method = %method,
        original_uri = %uri,
        target_host = %target_host,
        full_url = %full_url,
        "Processing HTTPS request extracted from TLS stream"
    );
    
    // Update the request URI to the full HTTPS URL for forwarding
    *req.uri_mut() = full_url.parse().map_err(|e| anyhow!("Invalid URL: {}", e))?;
    
    // Now process this exactly like a regular HTTP request through our chunking logic
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();
    
    let request_size = body_bytes.len();
    debug!(
        method = %method,
        full_url = %full_url,
        request_size = %request_size,
        chunk_size = %config.chunk_size,
        will_chunk = %(request_size > config.chunk_size),
        "HTTPS request body collected"
    );

    let result = if body_bytes.len() > config.chunk_size {
        // Big HTTPS request, needs chunking
        info!(
            method = %method,
            full_url = %full_url,
            request_size = %request_size,
            chunk_size = %config.chunk_size,
            "HTTPS request will be chunked"
        );
        chunk_and_send_request(parts, body_bytes, config).await
    } else {
        // Small HTTPS request, forward as single request
        debug!(
            method = %method,
            full_url = %full_url,
            request_size = %request_size,
            "HTTPS request will be forwarded as single request"
        );
        forward_single_request(parts, body_bytes, config).await
    };

    let duration = start_time.elapsed();
    match &result {
        Ok(response) => {
            info!(
                method = %method,
                full_url = %full_url,
                status = %response.status(),
                duration_ms = %duration.as_millis(),
                "HTTPS request completed successfully"
            );
        }
        Err(error) => {
            error!(
                method = %method,
                full_url = %full_url,
                error = %error,
                duration_ms = %duration.as_millis(),
                "HTTPS request failed"
            );
        }
    }

    result
}
