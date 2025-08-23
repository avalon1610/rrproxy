use anyhow::Result;
use bytes::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming, Request, Response};
use hyper_util::rt::TokioIo;
use http_body_util::{BodyExt, Full};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::AsyncReadExt;
use tracing::{debug, info, warn};

use super::config::LocalProxyConfig;
use super::https::handle_connect_request as handle_connect_raw;
use super::chunking::{chunk_and_send_request, forward_single_request, handle_connect_request};
use crate::utils::stream::ReconstructedStream;

pub async fn start(config: LocalProxyConfig) -> Result<()> {
    let listen_addr: SocketAddr = config.listen_addr.parse()?;
    let listener = TcpListener::bind(listen_addr).await?;
    info!("Local proxy listening on {}", listen_addr);

    let config = Arc::new(config);

    loop {
        let (stream, _) = listener.accept().await?;
        let config = Arc::clone(&config);

        tokio::task::spawn(async move {
            if let Err(err) = handle_raw_connection(stream, config).await {
                warn!("Error handling connection: {:?}", err);
            }
        });
    }
}

async fn handle_raw_connection(mut stream: TcpStream, config: Arc<LocalProxyConfig>) -> Result<()> {
    // Read enough data to determine if it's a CONNECT request
    let mut buffer = vec![0u8; 1024];
    let n = stream.read(&mut buffer).await?;
    
    if n == 0 {
        return Ok(());
    }
    
    let request_data = String::from_utf8_lossy(&buffer[..n]);
    
    if request_data.starts_with("CONNECT ") {
        // Handle CONNECT request
        info!("Handling CONNECT request");
        handle_connect_raw(stream, request_data.to_string(), config).await
    } else {
        // Handle HTTP request - reconstruct the stream and use hyper
        let reconstructed_stream = ReconstructedStream::new(buffer[..n].to_vec(), stream);
        let io = TokioIo::new(reconstructed_stream);
        
        if let Err(err) = http1::Builder::new()
            .serve_connection(io, service_fn(move |req| handle_http_request(req, Arc::clone(&config))))
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
