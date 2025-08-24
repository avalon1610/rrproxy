use anyhow::Result;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{info, warn};

use super::chunking::{handle_request, ChunkStore};
use super::config::RemoteProxyConfig;
use crate::utils::stream::ReconstructedStream;

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

    // Handle HTTP request - reconstruct the stream and use hyper
    let reconstructed_stream = ReconstructedStream::new(buffer[..n].to_vec(), stream);
    let io = TokioIo::new(reconstructed_stream);

    if let Err(err) = http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req| handle_request(req, Arc::clone(&chunk_store))),
        )
        .await
    {
        warn!("Error serving HTTP connection: {:?}", err);
    }
    Ok(())
}
