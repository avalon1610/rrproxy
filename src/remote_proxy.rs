use crate::common::*;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming, Request, Response, Method};
use hyper_util::rt::TokioIo;
use reqwest::Client;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn, error};

#[derive(Parser, Debug, Clone)]
pub struct RemoteProxyConfig {
    #[clap(short, long, default_value = "127.0.0.1:8081")]
    pub listen_addr: String,
    #[clap(long, default_value = "info")]
    pub log_level: String,
    #[clap(long)]
    pub log_file: Option<String>,
}

type ChunkStore = Arc<Mutex<HashMap<String, Vec<(usize, Bytes)>>>>;

pub async fn start(config: RemoteProxyConfig) -> Result<()> {
    let listen_addr: SocketAddr = config.listen_addr.parse()?;
    let listener = TcpListener::bind(listen_addr).await?;
    info!("Remote proxy listening on {}", listen_addr);

    let chunk_store: ChunkStore = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (stream, _) = listener.accept().await?;
        let chunk_store = Arc::clone(&chunk_store);

        tokio::task::spawn(async move {
            if let Err(err) = handle_raw_connection(stream, chunk_store).await {
                warn!("Error handling connection: {:?}", err);
            }
        });
    }
}

async fn handle_raw_connection(mut stream: TcpStream, chunk_store: ChunkStore) -> Result<()> {
    // Read enough data to determine if it's a CONNECT request
    let mut buffer = vec![0u8; 1024];
    let n = stream.read(&mut buffer).await?;
    
    if n == 0 {
        return Ok(());
    }
    
    let request_data = String::from_utf8_lossy(&buffer[..n]);
    
    if request_data.starts_with("CONNECT ") {
        // Handle CONNECT request
        info!("Handling CONNECT request from local proxy");
        handle_connect_tunnel(stream, request_data.to_string()).await
    } else {
        // Handle HTTP request - reconstruct the stream and use hyper
        let reconstructed_stream = ReconstructedStream::new(buffer[..n].to_vec(), stream);
        let io = TokioIo::new(reconstructed_stream);
        
        if let Err(err) = http1::Builder::new()
            .serve_connection(io, service_fn(move |req| handle_request(req, Arc::clone(&chunk_store))))
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

async fn handle_connect_tunnel(mut local_stream: TcpStream, request_data: String) -> Result<()> {
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
    
    // Look for X-Original-Url header and X-Proxy-Type header
    let mut actual_target = target;
    let mut is_https_tunnel = false;
    
    for line in &lines {
        if line.starts_with("X-Original-Url:") {
            if let Some(url) = line.split(": ").nth(1) {
                actual_target = url;
            }
        } else if line.starts_with("X-Proxy-Type:") {
            if let Some(proxy_type) = line.split(": ").nth(1) {
                if proxy_type == "https-tunnel" {
                    is_https_tunnel = true;
                }
            }
        }
    }
    
    info!("Remote proxy handling CONNECT - target: {}, is_https_tunnel: {}", actual_target, is_https_tunnel);
    
    // If we haven't received the complete headers, read more
    if !request_data.contains("\r\n\r\n") {
        let mut additional_buffer = vec![0u8; 1024];
        let n = local_stream.read(&mut additional_buffer).await?;
        if n > 0 {
            // We can ignore the additional headers for CONNECT
        }
    }
    
    // For HTTPS tunnels, we extract the hostname and port from the target
    let target_host_port = if is_https_tunnel {
        // Extract hostname from https:// URL or use target directly
        if actual_target.starts_with("https://") {
            let url = actual_target.strip_prefix("https://").unwrap_or(actual_target);
            if url.contains('/') {
                url.split('/').next().unwrap_or(target)
            } else {
                url
            }
        } else {
            target // Use the CONNECT target (e.g., "www.baidu.com:443")
        }
    } else {
        actual_target
    };
    
    info!("Remote proxy establishing connection to target: {}", target_host_port);
    
    // Connect to the actual target server
    let target_stream = match TcpStream::connect(target_host_port).await {
        Ok(stream) => stream,
        Err(e) => {
            error!("Failed to connect to target {}: {}", target_host_port, e);
            let error_response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            local_stream.write_all(error_response.as_bytes()).await?;
            return Err(anyhow!("Failed to connect to target: {}", e));
        }
    };
    
    info!("Successfully connected to target {}", target_host_port);
    
    // Send 200 Connection Established to local proxy
    let success_response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    local_stream.write_all(success_response.as_bytes()).await?;
    
    if is_https_tunnel {
        info!("Starting HTTPS tunnel between local proxy and {}", target_host_port);
    } else {
        info!("Starting tunnel between local proxy and {}", target_host_port);
    }
    
    // Start bidirectional copying between local proxy and target
    let (mut local_read, mut local_write) = local_stream.into_split();
    let (mut target_read, mut target_write) = target_stream.into_split();
    
    let local_to_target = tokio::io::copy(&mut local_read, &mut target_write);
    let target_to_local = tokio::io::copy(&mut target_read, &mut local_write);
    
    // Run both copy operations concurrently
    let result = tokio::select! {
        result1 = local_to_target => {
            debug!("Local to target copy completed: {:?}", result1);
            result1
        }
        result2 = target_to_local => {
            debug!("Target to local copy completed: {:?}", result2);
            result2
        }
    };
    
    match result {
        Ok(bytes_copied) => {
            info!("Tunnel completed for {}, {} bytes transferred", target_host_port, bytes_copied);
        }
        Err(e) => {
            debug!("Tunnel copy error for {}: {}", target_host_port, e);
        }
    }
    
    Ok(())
}

async fn handle_request(
    req: Request<Incoming>,
    chunk_store: ChunkStore,
) -> Result<Response<Full<Bytes>>> {
    let start_time = Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    
    debug!(
        method = %method,
        uri = %uri,
        headers = ?headers,
        "Handling remote request"
    );

    // CONNECT requests are now handled in handle_raw_connection, so we shouldn't get them here
    if method == Method::CONNECT {
        warn!("CONNECT request received in HTTP handler - this should not happen");
        return Ok(Response::builder()
            .status(400)
            .body(Full::new(Bytes::from("Bad Request")))?);
    }
    
    let result = if req.headers().contains_key(TRANSACTION_ID_HEADER) {
        let transaction_id = headers.get(TRANSACTION_ID_HEADER)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown");
        
        debug!(
            method = %method,
            uri = %uri,
            transaction_id = %transaction_id,
            "Processing chunked request"
        );
        
        // It's a chunked request
        assemble_and_forward(req, chunk_store).await
    } else {
        debug!(
            method = %method,
            uri = %uri,
            "Processing single request"
        );
        
        // It's a single request, forward it
        forward_request(req).await
    };

    let duration = start_time.elapsed();
    
    match &result {
        Ok(response) => {
            info!(
                method = %method,
                uri = %uri,
                status = %response.status(),
                duration_ms = %duration.as_millis(),
                result = "success",
                "Remote request completed successfully"
            );
        }
        Err(error) => {
            error!(
                method = %method,
                uri = %uri,
                error = %error,
                duration_ms = %duration.as_millis(),
                result = "error",
                "Remote request failed"
            );
        }
    }
    
    result
}

async fn forward_request(req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();
    
    // Check if there's an X-Original-Url header for the actual target URL
    let original_url = if let Some(header_value) = parts.headers.get("X-Original-Url") {
        header_value.to_str()?.to_string()
    } else {
        parts.uri.to_string() // Fallback to URI if no header
    };
    
    debug!(
        method = %parts.method,
        original_url = %original_url,
        body_size = %body_bytes.len(),
        "Forwarding request to target server"
    );
    
    let forward_start = Instant::now();
    
    // Build reqwest client - it will automatically handle HTTPS if the URL starts with https://
    let client = Client::builder()
        .danger_accept_invalid_certs(false) // Accept valid certs only
        .build()?;
    
    let result = client.request(parts.method.clone(), &original_url)
        .headers(parts.headers.clone())
        .body(body_bytes.clone())
        .send()
        .await;
    
    let forward_duration = forward_start.elapsed();
    
    match result {
        Ok(response) => {
            let status = response.status();
            let headers = response.headers().clone();
            
            debug!(
                method = %parts.method,
                original_url = %original_url,
                status = %status,
                duration_ms = %forward_duration.as_millis(),
                "Received response from target server"
            );
            
            let body = response.bytes().await?;
            
            info!(
                method = %parts.method,
                original_url = %original_url,
                status = %status,
                request_size = %body_bytes.len(),
                response_size = %body.len(),
                duration_ms = %forward_duration.as_millis(),
                protocol = %if original_url.starts_with("https://") { "HTTPS" } else { "HTTP" },
                "Request forwarded successfully"
            );

            let mut builder = Response::builder().status(status);
            for (key, value) in headers.iter() {
                builder = builder.header(key, value);
            }
            builder.body(Full::new(body)).map_err(|e| anyhow!(e))
        }
        Err(error) => {
            error!(
                method = %parts.method,
                original_url = %original_url,
                error = %error,
                duration_ms = %forward_duration.as_millis(),
                "Failed to forward request to target server"
            );
            Err(anyhow!(error))
        }
    }
}


async fn assemble_and_forward(
    req: Request<Incoming>,
    chunk_store: ChunkStore,
) -> Result<Response<Full<Bytes>>> {
    let (parts, body) = req.into_parts();
    let headers = parts.headers;
    let transaction_id = headers[TRANSACTION_ID_HEADER].to_str()?.to_string();
    let chunk_index: usize = headers[CHUNK_INDEX_HEADER].to_str()?.parse()?;
    let total_chunks: usize = headers[TOTAL_CHUNKS_HEADER].to_str()?.parse()?;
    let is_last: bool = headers[IS_LAST_CHUNK_HEADER].to_str()?.parse()?;
    let original_url = headers["X-Original-Url"].to_str()?.to_string();

    let body_bytes = body.collect().await?.to_bytes();

    debug!(
        transaction_id = %transaction_id,
        chunk_index = %chunk_index,
        total_chunks = %total_chunks,
        chunk_size = %body_bytes.len(),
        is_last = %is_last,
        original_url = %original_url,
        "Processing chunk"
    );

    let mut store = chunk_store.lock().await;
    let chunks = store.entry(transaction_id.clone()).or_insert_with(Vec::new);
    chunks.push((chunk_index, body_bytes.clone()));

    debug!(
        transaction_id = %transaction_id,
        chunks_received = %chunks.len(),
        total_expected = %total_chunks,
        "Chunk stored"
    );

    if is_last {
        if chunks.len() == total_chunks {
            // We have all chunks, assemble and forward
            chunks.sort_by_key(|(idx, _)| *idx);
            let full_body: Vec<u8> = chunks.iter().flat_map(|(_, data)| data.iter()).cloned().collect();
            store.remove(&transaction_id);
            drop(store); // Release lock

            info!(
                transaction_id = %transaction_id,
                assembled_size = %full_body.len(),
                total_chunks = %total_chunks,
                original_url = %original_url,
                "Request assembly completed, forwarding to target server"
            );

            let forward_start = Instant::now();
            let client = Client::builder()
                .danger_accept_invalid_certs(false) // Accept valid certs only
                .build()?;
            let result = client.request(parts.method.clone(), &original_url)
                .headers(headers.clone())
                .body(full_body.clone())
                .send()
                .await;
            
            let forward_duration = forward_start.elapsed();

            match result {
                Ok(response) => {
                    let status = response.status();
                    let response_headers = response.headers().clone();
                    let response_body = response.bytes().await?;
                    
                    info!(
                        transaction_id = %transaction_id,
                        method = %parts.method,
                        original_url = %original_url,
                        status = %status,
                        request_size = %full_body.len(),
                        response_size = %response_body.len(),
                        duration_ms = %forward_duration.as_millis(),
                        "Assembled request forwarded successfully"
                    );

                    let mut builder = Response::builder().status(status);
                    for (key, value) in response_headers.iter() {
                        builder = builder.header(key, value);
                    }
                    builder.body(Full::new(response_body)).map_err(|e| anyhow!(e))
                }
                Err(error) => {
                    error!(
                        transaction_id = %transaction_id,
                        method = %parts.method,
                        original_url = %original_url,
                        error = %error,
                        duration_ms = %forward_duration.as_millis(),
                        "Failed to forward assembled request"
                    );
                    Err(anyhow!(error))
                }
            }
        } else {
            // Error case: last chunk received but not all chunks are present
            warn!(
                transaction_id = %transaction_id,
                chunks_received = %chunks.len(),
                total_expected = %total_chunks,
                "Last chunk received but incomplete chunked transfer"
            );
            store.remove(&transaction_id);
            Err(anyhow!("Incomplete chunked transfer"))
        }
    } else {
        // Not the last chunk, just acknowledge
        debug!(
            transaction_id = %transaction_id,
            chunk_index = %chunk_index,
            "Chunk acknowledged, waiting for more"
        );
        Ok(Response::new(Full::new(Bytes::new())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::sync::Mutex;
    use bytes::Bytes;

    #[test]
    fn test_remote_proxy_config_creation() {
        let config = RemoteProxyConfig {
            listen_addr: "127.0.0.1:8081".to_string(),
            log_level: "info".to_string(),
            log_file: None,
        };
        
        assert_eq!(config.listen_addr, "127.0.0.1:8081");
        assert_eq!(config.log_level, "info");
        assert_eq!(config.log_file, None);
    }

    #[tokio::test]
    async fn test_chunk_store_operations() {
        let chunk_store: ChunkStore = Arc::new(Mutex::new(HashMap::new()));
        let transaction_id = "test-transaction".to_string();
        
        // Add some chunks
        {
            let mut store = chunk_store.lock().await;
            let chunks = store.entry(transaction_id.clone()).or_insert_with(Vec::new);
            chunks.push((0, Bytes::from("Hello, ")));
            chunks.push((1, Bytes::from("World!")));
        }
        
        // Verify chunks are stored
        {
            let store = chunk_store.lock().await;
            let chunks = store.get(&transaction_id).unwrap();
            assert_eq!(chunks.len(), 2);
            assert_eq!(chunks[0].0, 0);
            assert_eq!(chunks[1].0, 1);
        }
        
        // Test assembly
        {
            let mut store = chunk_store.lock().await;
            let chunks = store.get_mut(&transaction_id).unwrap();
            chunks.sort_by_key(|(idx, _)| *idx);
            let full_body: Vec<u8> = chunks.iter().flat_map(|(_, data)| data.iter()).cloned().collect();
            let assembled = String::from_utf8(full_body).unwrap();
            assert_eq!(assembled, "Hello, World!");
        }
    }

    #[tokio::test]
    async fn test_chunk_reassembly_order() {
        let chunk_store: ChunkStore = Arc::new(Mutex::new(HashMap::new()));
        let transaction_id = "test-order".to_string();
        
        // Add chunks out of order
        {
            let mut store = chunk_store.lock().await;
            let chunks = store.entry(transaction_id.clone()).or_insert_with(Vec::new);
            chunks.push((2, Bytes::from("!")));
            chunks.push((0, Bytes::from("Hello")));
            chunks.push((1, Bytes::from(", World")));
        }
        
        // Test that sorting works correctly
        {
            let mut store = chunk_store.lock().await;
            let chunks = store.get_mut(&transaction_id).unwrap();
            chunks.sort_by_key(|(idx, _)| *idx);
            
            assert_eq!(chunks[0].0, 0);
            assert_eq!(chunks[1].0, 1);
            assert_eq!(chunks[2].0, 2);
            
            let full_body: Vec<u8> = chunks.iter().flat_map(|(_, data)| data.iter()).cloned().collect();
            let assembled = String::from_utf8(full_body).unwrap();
            assert_eq!(assembled, "Hello, World!");
        }
    }
}
