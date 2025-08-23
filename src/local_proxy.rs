use crate::common::*;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming, Request, Response, Uri};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tracing::{debug, info, warn, error};
use uuid::Uuid;

#[derive(Parser, Debug, Clone)]
pub struct LocalProxyConfig {
    #[clap(long, default_value = "127.0.0.1:8080")]
    pub listen_addr: String,
    #[clap(long, default_value = "http://127.0.0.1:8081")]
    pub remote_addr: String,
    #[clap(long, default_value_t = 10240)] // 10KB
    pub chunk_size: usize,
    #[clap(long)]
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
        let io = TokioIo::new(stream);
        let config = Arc::clone(&config);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(move |req| handle_request(req, Arc::clone(&config))))
                .await
            {
                warn!("Error serving connection: {:?}", err);
            }
        });
    }
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

async fn forward_single_request(
    mut parts: http::request::Parts,
    body: Bytes,
    config: Arc<LocalProxyConfig>,
) -> Result<Response<Full<Bytes>>> {
    let remote_uri: Uri = config.remote_addr.parse()?;
    parts.uri = remote_uri;
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
