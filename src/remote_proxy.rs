use crate::common::*;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming, Request, Response};
use hyper_util::rt::TokioIo;
use reqwest::Client;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tokio::net::TcpListener;
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
        let io = TokioIo::new(stream);
        let chunk_store = Arc::clone(&chunk_store);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(move |req| handle_request(req, Arc::clone(&chunk_store))))
                .await
            {
                warn!("Error serving connection: {:?}", err);
            }
        });
    }
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
        "Forwarding single request to target server"
    );
    
    let forward_start = Instant::now();
    let client = Client::new();
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
                "Single request forwarded successfully"
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
            let client = Client::new();
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
