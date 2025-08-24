use anyhow::{anyhow, Result};
use bytes::Bytes;
use hyper::{HeaderMap, Method, body::Incoming, Request, Response};
use http_body_util::{BodyExt, Full};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, error};
use uuid::Uuid;
use crate::common::*;
use super::config::LocalProxyConfig;
use crate::log_debug_request;

pub async fn chunk_and_send_request(
    parts: hyper::http::request::Parts,
    body_bytes: Bytes,
    config: Arc<LocalProxyConfig>,
) -> Result<hyper::Response<http_body_util::Full<Bytes>>> {
    let start_time = Instant::now();
    let method = &parts.method;
    let uri = &parts.uri;
    let headers = &parts.headers;

    let transaction_id = Uuid::new_v4().to_string();
    let chunk_size = config.chunk_size;
    let total_chunks = (body_bytes.len() + chunk_size - 1) / chunk_size;

    info!(
        method = %method,
        uri = %uri,
        transaction_id = %transaction_id,
        body_size = %body_bytes.len(),
        chunk_size = %chunk_size,
        total_chunks = %total_chunks,
        "Chunking large request"
    );

    // Log detailed request information at debug level
    log_debug_request!(method, uri, headers, body_bytes);

    // Send chunks
    let mut chunk_index = 0;
    let mut start_pos = 0;

    while start_pos < body_bytes.len() {
        let end_pos = std::cmp::min(start_pos + chunk_size, body_bytes.len());
        let chunk = body_bytes.slice(start_pos..end_pos);
        let is_last_chunk = end_pos >= body_bytes.len();

        debug!(
            transaction_id = %transaction_id,
            chunk_index = %chunk_index,
            chunk_size = %chunk.len(),
            is_last_chunk = %is_last_chunk,
            "Sending chunk"
        );

        let chunk_response = send_chunk(
            method.clone(),
            uri.clone(),
            headers.clone(),
            chunk,
            &transaction_id,
            chunk_index,
            total_chunks,
            is_last_chunk,
            Arc::clone(&config),
        )
        .await?;

        // For chunked requests, we only care about the response from the last chunk
        if is_last_chunk {
            let duration = start_time.elapsed();
            info!(
                method = %method,
                uri = %uri,
                transaction_id = %transaction_id,
                duration_ms = %duration.as_millis(),
                "Chunked request completed"
            );
            return Ok(chunk_response);
        }

        chunk_index += 1;
        start_pos = end_pos;
    }

    Err(anyhow!("No chunks were sent"))
}

pub async fn forward_single_request(
    parts: hyper::http::request::Parts,
    body_bytes: Bytes,
    config: Arc<LocalProxyConfig>,
) -> Result<hyper::Response<http_body_util::Full<Bytes>>> {
    let start_time = Instant::now();
    let method = &parts.method;
    let uri = &parts.uri;
    let mut headers = parts.headers.clone();

    debug!(
        method = %method,
        uri = %uri,
        body_size = %body_bytes.len(),
        "Forwarding single request to remote proxy"
    );

    // Log detailed request information at debug level
    log_debug_request!(method, uri, headers, body_bytes);

    // Add the original URL header so remote proxy knows where to forward
    headers.insert(ORIGINAL_URL_HEADER, uri.to_string().parse()?);

    // Send to remote proxy (remote proxy will use X-Original-Url) 
    let response = send_single_request(
        method.clone(),
        config.remote_addr.parse()?,
        headers,
        body_bytes,
        config,
    )
    .await?;

    let duration = start_time.elapsed();
    debug!(
        method = %method,
        uri = %uri,
        duration_ms = %duration.as_millis(),
        "Single request completed"
    );

    Ok(response)
}

async fn send_chunk(
    method: Method,
    uri: hyper::Uri,
    mut headers: HeaderMap,
    chunk: Bytes,
    transaction_id: &str,
    chunk_index: usize,
    total_chunks: usize,
    is_last_chunk: bool,
    config: Arc<LocalProxyConfig>,
) -> Result<hyper::Response<http_body_util::Full<Bytes>>> {
    // Add chunking headers
    headers.insert(TRANSACTION_ID_HEADER, transaction_id.parse()?);
    headers.insert(CHUNK_INDEX_HEADER, chunk_index.to_string().parse()?);
    headers.insert(TOTAL_CHUNKS_HEADER, total_chunks.to_string().parse()?);
    headers.insert(IS_LAST_CHUNK_HEADER, is_last_chunk.to_string().parse()?);
    headers.insert(ORIGINAL_URL_HEADER, uri.to_string().parse()?);

    // Send to remote proxy (remote proxy will use X-Original-Url)
    send_single_request(method, config.remote_addr.parse()?, headers, chunk, config).await
}

async fn send_single_request(
    method: Method,
    remote_uri: hyper::Uri,
    headers: HeaderMap,
    body_bytes: Bytes,
    config: Arc<LocalProxyConfig>,
) -> Result<hyper::Response<http_body_util::Full<Bytes>>> {
    use http_body_util::Full;

    debug!(
        method = %method,
        remote_uri = %remote_uri,
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
    let mut req_builder = client.request(method.clone(), remote_uri.to_string());

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
            let response_headers = response.headers().clone();
            debug!(
                method = %method,
                remote_uri = %remote_uri,
                status = %status,
                duration_ms = %send_duration.as_millis(),
                "Received response from remote proxy"
            );

            let mut builder = hyper::Response::builder().status(status);

            // Copy headers
            for (name, value) in response_headers.iter() {
                builder = builder.header(name, value);
            }

            // Get body
            let response_body = response.bytes().await?;

            debug!(
                method = %method,
                remote_uri = %remote_uri,
                response_size = %response_body.len(),
                "Response body received"
            );

            // Log detailed response information at debug level
            tracing::debug!(
                method = %method,
                uri = %remote_uri,
                status = %status,
                headers = ?response_headers,
                body_info = %crate::logging::format_body_info(&response_body),
                "Full response details from remote proxy"
            );

            Ok(builder.body(Full::new(response_body))?)
        }
        Err(error) => {
            error!(
                method = %method,
                remote_uri = %remote_uri,
                error = %error,
                duration_ms = %send_duration.as_millis(),
                "Failed to send request to remote proxy"
            );
            Err(anyhow!(error))
        }
    }
}

pub async fn handle_connect_request(
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

#[cfg(test)]
mod tests {
    use bytes::Bytes;

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
