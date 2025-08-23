use anyhow::{anyhow, Result};
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tracing::{debug, info};
use hyper::{body::Incoming, Request, Response};
use http_body_util::{BodyExt, Full};

use crate::common::*;

pub type ChunkStore = Arc<Mutex<HashMap<String, Vec<(usize, Bytes)>>>>;

pub async fn handle_request(
    req: Request<Incoming>,
    chunk_store: ChunkStore,
) -> Result<Response<Full<Bytes>>> {
    let _start_time = Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers();

    // CONNECT requests are now handled in handle_raw_connection, so we shouldn't get them here
    if method == hyper::Method::CONNECT {
        tracing::warn!("CONNECT request received in HTTP handler - this should not happen");
        return Ok(Response::builder()
            .status(400)
            .body(Full::new(Bytes::from("Bad Request")))?);
    }

    // Check if this is a chunked request
    let is_chunked = headers.contains_key(TRANSACTION_ID_HEADER);

    if is_chunked {
        debug!(
            method = %method,
            uri = %uri,
            "Processing chunked request"
        );
        handle_chunked_request(req, chunk_store).await
    } else {
        debug!(
            method = %method,
            uri = %uri,
            "Processing single request"
        );
        handle_single_request(req).await
    }
}

async fn handle_chunked_request(
    req: Request<Incoming>,
    chunk_store: ChunkStore,
) -> Result<Response<Full<Bytes>>> {
    // Extract headers before consuming the request
    let transaction_id = req.headers()
        .get(TRANSACTION_ID_HEADER)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| anyhow!("Missing transaction ID"))?
        .to_string();
    
    let chunk_index: usize = req.headers()
        .get(CHUNK_INDEX_HEADER)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("Invalid chunk index"))?;
    
    let total_chunks: usize = req.headers()
        .get(TOTAL_CHUNKS_HEADER)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("Invalid total chunks"))?;
    
    let is_last_chunk: bool = req.headers()
        .get(IS_LAST_CHUNK_HEADER)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(false);
    
    let original_url = req.headers()
        .get("X-Original-Url")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| anyhow!("Missing original URL"))?
        .to_string();

    debug!(
        transaction_id = %transaction_id,
        chunk_index = %chunk_index,
        total_chunks = %total_chunks,
        is_last_chunk = %is_last_chunk,
        original_url = %original_url,
        "Processing chunk"
    );

    // Get the chunk body
    let (parts, body) = req.into_parts();
    let chunk_bytes = body.collect().await?.to_bytes();

    debug!(
        transaction_id = %transaction_id,
        chunk_index = %chunk_index,
        chunk_size = %chunk_bytes.len(),
        "Chunk body collected"
    );

        // Store the chunk
        {
            let mut store = chunk_store.lock().await;
            let chunks = store.entry(transaction_id.clone()).or_insert_with(Vec::new);
            chunks.push((chunk_index, chunk_bytes));
            
            debug!(
                transaction_id = %transaction_id,
                stored_chunks = %chunks.len(),
                total_expected = %total_chunks,
                "Chunk stored"
            );
        }

        // If this is the last chunk, reassemble and forward the request
        if is_last_chunk {
            info!(
                transaction_id = %transaction_id,
                total_chunks = %total_chunks,
                "Last chunk received, reassembling request"
            );
            
            // Remove chunks from store and reassemble
            let chunks = {
                let mut store = chunk_store.lock().await;
                store.remove(&transaction_id).unwrap_or_default()
            };        // Sort chunks by index and concatenate
        let mut sorted_chunks = chunks;
        sorted_chunks.sort_by_key(|&(index, _)| index);
        
        let mut reassembled_body = Vec::new();
        for (index, chunk) in sorted_chunks {
            debug!(
                transaction_id = %transaction_id,
                chunk_index = %index,
                chunk_size = %chunk.len(),
                "Adding chunk to reassembled body"
            );
            reassembled_body.extend_from_slice(&chunk);
        }

            info!(
                transaction_id = %transaction_id,
                reassembled_size = %reassembled_body.len(),
                original_url = %original_url,
                "Request reassembled, forwarding to target"
            );

            // Create a new request with the reassembled body
            let mut new_req_builder = reqwest::Client::new().request(
                parts.method.clone(),
                &original_url,
            );        // Copy original headers (except our chunking headers)
        for (name, value) in parts.headers.iter() {
            if !name.as_str().starts_with("X-") || name.as_str() == "X-Forwarded-For" {
                new_req_builder = new_req_builder.header(name, value);
            }
        }

        new_req_builder = new_req_builder.body(reassembled_body);

        // Forward the reassembled request
        forward_request_to_target(new_req_builder).await
    } else {
        // Not the last chunk, return acknowledgment
        debug!(
            transaction_id = %transaction_id,
            chunk_index = %chunk_index,
            "Chunk acknowledged, waiting for more"
        );
        
        Ok(Response::builder()
            .status(200)
            .body(Full::new(Bytes::from("Chunk received")))?)
    }
}

async fn handle_single_request(req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    
    debug!(
        method = %method,
        uri = %uri,
        "Processing single request from local proxy"
    );

    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();

    // Check if this request came from local proxy (has X-Original-Url header)
    let target_url = if let Some(original_url) = parts.headers.get(ORIGINAL_URL_HEADER) {
        let url = original_url.to_str()
            .map_err(|_| anyhow!("Invalid X-Original-Url header"))?
            .to_string();
        debug!(
            method = %method,
            original_uri = %uri,
            target_url = %url,
            "Using X-Original-Url for target"
        );
        url
    } else {
        // Direct request to remote proxy (not from local proxy)
        let url = parts.uri.to_string();
        debug!(
            method = %method,
            uri = %uri,
            "Direct request to remote proxy, using request URI"
        );
        url
    };

    let mut req_builder = reqwest::Client::new().request(
        parts.method.clone(),
        target_url,
    );

    // Copy headers (except our internal ones)
    for (name, value) in parts.headers.iter() {
        if name.as_str() != ORIGINAL_URL_HEADER {
            req_builder = req_builder.header(name, value);
        }
    }

    req_builder = req_builder.body(body_bytes.to_vec());

    forward_request_to_target(req_builder).await
}

async fn forward_request_to_target(
    req_builder: reqwest::RequestBuilder,
) -> Result<Response<Full<Bytes>>> {
    let start_time = Instant::now();
    
    let response = req_builder.send().await?;
    let duration = start_time.elapsed();
    
    let status = response.status();
    debug!(
        status = %status,
        duration_ms = %duration.as_millis(),
        "Response received from target server"
    );

    let mut builder = Response::builder().status(status);

    // Copy response headers
    for (name, value) in response.headers().iter() {
        builder = builder.header(name, value);
    }

    let response_body = response.bytes().await?;
    
    debug!(
        response_size = %response_body.len(),
        "Response body received from target"
    );

    Ok(builder.body(Full::new(response_body))?)
}
