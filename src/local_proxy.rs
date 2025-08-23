use crate::common::*;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming, Request, Response, Uri, Method};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn, error};
use uuid::Uuid;
use native_tls::{Identity, TlsAcceptor};
use tokio_native_tls::TlsAcceptor as TokioTlsAcceptor;
use std::fs;

#[derive(Parser, Debug, Clone)]
pub struct LocalProxyConfig {
    #[clap(short, long, default_value = "127.0.0.1:8080")]
    pub listen_addr: String,
    #[clap(short, long, default_value = "http://127.0.0.1:8081")]
    pub remote_addr: String,
    #[clap(short, long, default_value_t = 10240)] // 10KB
    pub chunk_size: usize,
    #[clap(short, long)]
    pub firewall_proxy: Option<String>,
    #[clap(long, default_value = "info")]
    pub log_level: String,
    #[clap(long)]
    pub log_file: Option<String>,
}

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

fn create_tls_acceptor() -> Result<TokioTlsAcceptor> {
    // Read certificate and key files
    let cert_pem = fs::read("cert.pem")?;
    let key_pem = fs::read("key.pem")?;
    
    // Combine cert and key for PKCS#12 format
    let mut cert_and_key = Vec::new();
    cert_and_key.extend_from_slice(&cert_pem);
    cert_and_key.extend_from_slice(&key_pem);
    
    // Create identity from PEM data
    let identity = Identity::from_pkcs8(&cert_pem, &key_pem)?;
    
    // Create TLS acceptor
    let acceptor = TlsAcceptor::new(identity)?;
    let tokio_acceptor = TokioTlsAcceptor::from(acceptor);
    
    Ok(tokio_acceptor)
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
            .serve_connection(io, service_fn(move |req| handle_request(req, Arc::clone(&config))))
            .await
        {
            warn!("Error serving HTTP connection: {:?}", err);
        }
        Ok(())
    }
}

// A simple wrapper to reconstruct a stream from buffered data
struct ReconstructedStream {
    buffer: Vec<u8>,
    position: usize,
    stream: TcpStream,
}

impl ReconstructedStream {
    fn new(buffer: Vec<u8>, stream: TcpStream) -> Self {
        Self {
            buffer,
            position: 0,
            stream,
        }
    }
}

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

impl AsyncRead for ReconstructedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // First, serve data from our buffer
        if self.position < self.buffer.len() {
            let remaining_buffer = &self.buffer[self.position..];
            let to_copy = std::cmp::min(remaining_buffer.len(), buf.remaining());
            buf.put_slice(&remaining_buffer[..to_copy]);
            self.position += to_copy;
            return Poll::Ready(Ok(()));
        }
        
        // Then delegate to the underlying stream
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for ReconstructedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

async fn handle_connect_raw(mut client_stream: TcpStream, request_data: String, config: Arc<LocalProxyConfig>) -> Result<()> {
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
    
    if let Err(err) = http1::Builder::new()
        .serve_connection(io, service_fn(move |req| {
            handle_https_request(req, target_for_service.clone(), Arc::clone(&config_for_service))
        }))
        .await
    {
        warn!("Error serving HTTPS connection for {}: {:?}", target, err);
    }
    
    info!("HTTPS connection completed for target {}", target);
    Ok(())
}

async fn handle_https_request(
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
                request_size = %request_size,
                result = "success",
                "HTTPS request completed successfully"
            );
        }
        Err(error) => {
            error!(
                method = %method,
                full_url = %full_url,
                error = %error,
                duration_ms = %duration.as_millis(),
                request_size = %request_size,
                result = "error",
                "HTTPS request failed"
            );
        }
    }
    
    result
}

async fn handle_request(
    req: Request<Incoming>,
    config: Arc<LocalProxyConfig>,
) -> Result<Response<Full<Bytes>>> {
    let start_time = Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    
    info!(
        method = %method,
        uri = %uri,
        headers = ?headers,
        "Processing incoming request"
    );

    // Handle CONNECT requests for HTTPS tunneling
    if method == Method::CONNECT {
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
        "Request body collected"
    );

    let result = if body_bytes.len() > config.chunk_size {
        // Big request, needs chunking
        info!(
            method = %method,
            uri = %uri,
            request_size = %request_size,
            chunk_size = %config.chunk_size,
            "Request will be chunked"
        );
        chunk_and_send_request(parts, body_bytes, config).await
    } else {
        // Small request, forward as is
        debug!(
            method = %method,
            uri = %uri,
            request_size = %request_size,
            "Request will be forwarded as single request"
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
                request_size = %request_size,
                result = "success",
                "Request completed successfully"
            );
        }
        Err(error) => {
            error!(
                method = %method,
                uri = %uri,
                error = %error,
                duration_ms = %duration.as_millis(),
                request_size = %request_size,
                result = "error",
                "Request failed"
            );
        }
    }
    
    result
}

async fn handle_connect_request(
    req: Request<Incoming>,
    config: Arc<LocalProxyConfig>,
) -> Result<Response<Full<Bytes>>> {
    let uri = req.uri().clone();
    let target_host = uri.to_string();
    
    info!(
        method = "CONNECT",
        target = %target_host,
        "Handling CONNECT request for HTTPS tunnel"
    );
    
    // For CONNECT requests, we forward the request to the remote proxy
    // The remote proxy will establish the connection to the target server
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();
    
    forward_single_request(parts, body_bytes, config).await
}

async fn forward_single_request(
    mut parts: http::request::Parts,
    body: Bytes,
    config: Arc<LocalProxyConfig>,
) -> Result<Response<Full<Bytes>>> {
    let original_url = parts.uri.to_string();
    let remote_uri: Uri = config.remote_addr.parse()?;
    parts.uri = remote_uri;
    
    // Add the original URL as a header so the remote proxy knows where to forward
    parts.headers.insert("X-Original-Url", original_url.parse()?);
    
    let req = Request::from_parts(parts, Full::new(body));
    send_to_remote(req, &config).await
}

async fn chunk_and_send_request(
    parts: http::request::Parts,
    body: Bytes,
    config: Arc<LocalProxyConfig>,
) -> Result<Response<Full<Bytes>>> {
    let transaction_id = Uuid::new_v4().to_string();
    
    // Create chunks from the body
    let mut chunks = Vec::new();
    let chunk_size = config.chunk_size;
    let mut start = 0;
    
    while start < body.len() {
        let end = std::cmp::min(start + chunk_size, body.len());
        chunks.push(body.slice(start..end));
        start = end;
    }
    
    let total_chunks = chunks.len();
    
    info!(
        transaction_id = %transaction_id,
        total_size = %body.len(),
        total_chunks = %total_chunks,
        chunk_size = %chunk_size,
        "Starting chunked request transmission"
    );

    for (i, chunk) in chunks.into_iter().enumerate() {
        let is_last = i == total_chunks - 1;
        let mut new_req = Request::new(Full::new(chunk.clone()));
        *new_req.method_mut() = parts.method.clone();
        *new_req.uri_mut() = config.remote_addr.parse()?;
        *new_req.headers_mut() = parts.headers.clone();

        new_req
            .headers_mut()
            .insert(TRANSACTION_ID_HEADER, transaction_id.parse()?);
        new_req
            .headers_mut()
            .insert(CHUNK_INDEX_HEADER, i.to_string().parse()?);
        new_req
            .headers_mut()
            .insert(TOTAL_CHUNKS_HEADER, total_chunks.to_string().parse()?);
        new_req
            .headers_mut()
            .insert(IS_LAST_CHUNK_HEADER, is_last.to_string().parse()?);
        
        // Also need to add original URL to a header
        new_req
            .headers_mut()
            .insert("X-Original-Url", parts.uri.to_string().parse()?);

        debug!(
            transaction_id = %transaction_id,
            chunk_index = %i,
            total_chunks = %total_chunks,
            chunk_size = %chunk.len(),
            is_last = %is_last,
            "Sending chunk"
        );

        let chunk_start = Instant::now();
        let res = send_to_remote(new_req, &config).await;
        let chunk_duration = chunk_start.elapsed();
        
        match &res {
            Ok(response) => {
                debug!(
                    transaction_id = %transaction_id,
                    chunk_index = %i,
                    status = %response.status(),
                    duration_ms = %chunk_duration.as_millis(),
                    is_last = %is_last,
                    "Chunk sent successfully"
                );
                
                if is_last {
                    info!(
                        transaction_id = %transaction_id,
                        total_chunks = %total_chunks,
                        "All chunks sent successfully"
                    );
                    return res;
                } else {
                    if response.status() != 200 {
                        error!(
                            transaction_id = %transaction_id,
                            chunk_index = %i,
                            status = %response.status(),
                            "Remote proxy returned error for chunk"
                        );
                        return Err(anyhow!("Remote proxy returned error for chunk {}", i));
                    }
                }
            }
            Err(error) => {
                error!(
                    transaction_id = %transaction_id,
                    chunk_index = %i,
                    error = %error,
                    duration_ms = %chunk_duration.as_millis(),
                    "Failed to send chunk"
                );
                return res;
            }
        }
    }

    Err(anyhow!("Chunking logic error: should have returned a response"))
}

async fn send_to_remote(req: Request<Full<Bytes>>, config: &LocalProxyConfig) -> Result<Response<Full<Bytes>>> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let body = req.into_body();
    
    // Collect the body bytes
    let body_bytes = body.collect().await?.to_bytes();
    
    debug!(
        method = %method,
        uri = %uri,
        body_size = %body_bytes.len(),
        firewall_proxy = ?config.firewall_proxy,
        "Sending request to remote proxy"
    );
    
    // Build reqwest client with optional proxy
    let mut client_builder = reqwest::Client::builder();
    
    if let Some(proxy_url) = &config.firewall_proxy {
        debug!(proxy_url = %proxy_url, "Using firewall proxy");
        let proxy = reqwest::Proxy::all(proxy_url)?;
        client_builder = client_builder.proxy(proxy);
    }
    
    let client = client_builder.build()?;
    
    // Build the request
    let mut req_builder = client.request(method.clone(), uri.to_string());
    
    // Add headers
    for (name, value) in headers.iter() {
        req_builder = req_builder.header(name, value);
    }
    
    // Add body
    req_builder = req_builder.body(body_bytes.to_vec());
    
    let send_start = Instant::now();
    
    // Send the request
    let result = req_builder.send().await;
    let send_duration = send_start.elapsed();
    
    match result {
        Ok(response) => {
            let status = response.status();
            debug!(
                method = %method,
                uri = %uri,
                status = %status,
                duration_ms = %send_duration.as_millis(),
                "Received response from remote proxy"
            );
            
            let mut builder = Response::builder().status(status);
            
            // Copy headers
            for (name, value) in response.headers().iter() {
                builder = builder.header(name, value);
            }
            
            // Get body
            let response_body = response.bytes().await?;
            
            debug!(
                method = %method,
                uri = %uri,
                response_size = %response_body.len(),
                "Response body received"
            );
            
            Ok(builder.body(Full::new(response_body))?)
        }
        Err(error) => {
            error!(
                method = %method,
                uri = %uri,
                error = %error,
                duration_ms = %send_duration.as_millis(),
                "Failed to send request to remote proxy"
            );
            Err(anyhow!(error))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_local_proxy_config_creation() {
        let config = LocalProxyConfig {
            listen_addr: "127.0.0.1:8080".to_string(),
            remote_addr: "http://127.0.0.1:8081".to_string(),
            chunk_size: 1024,
            firewall_proxy: None,
            log_level: "info".to_string(),
            log_file: None,
        };
        
        assert_eq!(config.listen_addr, "127.0.0.1:8080");
        assert_eq!(config.remote_addr, "http://127.0.0.1:8081");
        assert_eq!(config.chunk_size, 1024);
        assert_eq!(config.firewall_proxy, None);
        assert_eq!(config.log_level, "info");
        assert_eq!(config.log_file, None);
    }

    #[test]
    fn test_local_proxy_config_with_firewall_proxy() {
        let config = LocalProxyConfig {
            listen_addr: "127.0.0.1:8080".to_string(),
            remote_addr: "http://127.0.0.1:8081".to_string(),
            chunk_size: 1024,
            firewall_proxy: Some("http://proxy.company.com:8080".to_string()),
            log_level: "debug".to_string(),
            log_file: Some("rrproxy.log".to_string()),
        };
        
        assert_eq!(config.firewall_proxy, Some("http://proxy.company.com:8080".to_string()));
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.log_file, Some("rrproxy.log".to_string()));
    }

    #[test]
    fn test_chunking_logic() {
        let body = Bytes::from("Hello, World! This is a test message that should be chunked.");
        let chunk_size = 10;
        
        // Simulate chunking logic
        let mut chunks = Vec::new();
        let mut start = 0;
        
        while start < body.len() {
            let end = std::cmp::min(start + chunk_size, body.len());
            chunks.push(body.slice(start..end));
            start = end;
        }
        
        assert!(chunks.len() > 1); // Should be chunked
        
        // Verify total length matches original
        let total_len: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total_len, body.len());
        
        // Verify chunks are correct size (except possibly the last one)
        for (i, chunk) in chunks.iter().enumerate() {
            if i < chunks.len() - 1 {
                assert_eq!(chunk.len(), chunk_size);
            } else {
                assert!(chunk.len() <= chunk_size);
            }
        }
    }

    #[test]
    fn test_small_body_no_chunking() {
        let body = Bytes::from("Hi");
        let chunk_size = 10;
        
        // Small body should not be chunked
        let mut chunks = Vec::new();
        let mut start = 0;
        
        while start < body.len() {
            let end = std::cmp::min(start + chunk_size, body.len());
            chunks.push(body.slice(start..end));
            start = end;
        }
        
        assert_eq!(chunks.len(), 1); // Should not be chunked
        assert_eq!(chunks[0], body);
    }
}
