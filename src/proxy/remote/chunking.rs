use anyhow::{anyhow, bail, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, Request, Response};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tracing::warn;
use tracing::{debug, info};

use crate::common::*;
use crate::log_debug_request;

pub type ChunkStore = Arc<Mutex<HashMap<String, Vec<(usize, Bytes)>>>>;

pub async fn handle_request(
    req: Request<Incoming>,
    chunk_store: ChunkStore,
) -> Result<Response<Full<Bytes>>> {
    let start_time = Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers();

    info!(
        method = %method,
        uri = %uri,
        "Processing incoming HTTP request"
    );

    if method == hyper::Method::CONNECT {
        return Ok(Response::builder().status(400).body(Full::new(Bytes::from(
            "Bad Request, Not support CONNECT method",
        )))?);
    }

    // Check if this is a chunked request
    let is_chunked = headers.contains_key(TRANSACTION_ID_HEADER);

    let result = if is_chunked {
        info!(
            method = %method,
            uri = %uri,
            "Processing chunked request"
        );
        handle_chunked_request(req, chunk_store).await
    } else {
        info!(
            method = %method,
            uri = %uri,
            "Processing single request"
        );
        handle_single_request(req).await
    };

    let duration = start_time.elapsed();
    match &result {
        Ok(response) => {
            if response.status().is_success() {
                info!(
                    method = %method,
                    uri = %uri,
                    status = %response.status(),
                    duration_ms = %duration.as_millis(),
                    "Request processed successfully"
                );
            } else {
                warn!(
                    method = %method,
                    uri = %uri,
                    status = %response.status(),
                    duration_ms = %duration.as_millis(),
                    "Request processed with non-success status"
                );
            }
        }
        Err(error) => {
            warn!(
                method = %method,
                uri = %uri,
                error = %error,
                duration_ms = %duration.as_millis(),
                "HTTP request forwarding failed"
            );
        }
    }

    result
}

async fn handle_chunked_request(
    req: Request<Incoming>,
    chunk_store: ChunkStore,
) -> Result<Response<Full<Bytes>>> {
    // Extract headers before consuming the request
    let transaction_id = req
        .headers()
        .get(TRANSACTION_ID_HEADER)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| anyhow!("Missing transaction ID"))?
        .to_string();

    let chunk_index: usize = req
        .headers()
        .get(CHUNK_INDEX_HEADER)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("Invalid chunk index"))?;

    let total_chunks: usize = req
        .headers()
        .get(TOTAL_CHUNKS_HEADER)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("Invalid total chunks"))?;

    let is_last_chunk: bool = req
        .headers()
        .get(IS_LAST_CHUNK_HEADER)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(false);

    let original_url = req
        .headers()
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

    // Log detailed chunk information at debug level
    let original_uri: hyper::Uri = original_url
        .parse()
        .unwrap_or_else(|_| "/".parse().unwrap());
    log_debug_request!(parts.method, original_uri, parts.headers, chunk_bytes);

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
        }; // Sort chunks by index and concatenate
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
            method = %parts.method,
            "Request reassembled, forwarding to target"
        );

        // Create a new request with the reassembled body
        let mut new_req_builder =
            reqwest::Client::new().request(parts.method.clone(), &original_url); // Copy original headers (except our chunking headers)
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

    info!(
        method = %method,
        uri = %uri,
        "Processing single request from local proxy"
    );

    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();

    // Log detailed request information at debug level
    log_debug_request!(method, uri, parts.headers, body_bytes);

    let request_size = body_bytes.len();

    // Check if this request came from local proxy (has X-Original-Url header)
    let target_url = if let Some(original_url) = parts.headers.get(ORIGINAL_URL_HEADER) {
        let url = original_url
            .to_str()
            .map_err(|_| anyhow!("Invalid X-Original-Url header"))?
            .to_string();
        info!(
            method = %method,
            original_uri = %uri,
            target_url = %url,
            request_size = %request_size,
            "Forwarding request to target URL"
        );
        url
    } else {
        warn!("no X-Original-Url header found");
        bail!("Missing X-Original-Url header");
    };

    let mut req_builder = reqwest::Client::new().request(parts.method.clone(), target_url);
    debug!("req_builder: {:?}", req_builder);

    // Copy headers (except our internal ones)
    for (name, value) in parts.headers.iter() {
        debug!("original header: {}: {:?}", name, value);
        if !is_reserved_header(name.as_str()) && name.as_str().to_ascii_lowercase() != "host" {
            req_builder = req_builder.header(name, value);
        }
    }

    debug!("req_builder: {:?}", req_builder);

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
    let response_headers = response.headers().clone();
    info!(
        status = %status,
        duration_ms = %duration.as_millis(),
        "Response received from target server"
    );

    let mut builder = Response::builder().status(status);

    // Copy response headers
    for (name, value) in response_headers.iter() {
        builder = builder.header(name, value);
    }

    let response_body = response.bytes().await?;

    info!(
        response_size = %response_body.len(),
        "Response body received from target"
    );

    // Log detailed response information at debug level
    tracing::debug!(
        status = %status,
        headers = ?response_headers,
        body_info = %crate::logging::format_body_info(&response_body),
        "Full response details from target server"
    );

    Ok(builder.body(Full::new(response_body))?)
}
