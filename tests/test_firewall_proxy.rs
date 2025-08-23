use anyhow::Result;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use http_body_util::{Full, BodyExt};
use bytes::Bytes;
use tokio::net::{TcpListener, TcpStream};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::{info, debug};

/// A simple HTTP proxy server for testing firewall proxy functionality
pub struct TestFirewallProxy {
    listen_addr: SocketAddr,
    request_count: Arc<AtomicU32>,
}

impl TestFirewallProxy {
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            request_count: Arc::new(AtomicU32::new(0)),
        }
    }

    pub fn get_request_count(&self) -> u32 {
        self.request_count.load(Ordering::Relaxed)
    }

    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        info!("Test firewall proxy listening on {}", self.listen_addr);

        let request_count = Arc::clone(&self.request_count);

        loop {
            let (stream, _) = listener.accept().await?;
            let request_count = Arc::clone(&request_count);

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(stream, request_count).await {
                    eprintln!("Error handling proxy connection: {}", e);
                }
            });
        }
    }

    async fn handle_connection(stream: TcpStream, request_count: Arc<AtomicU32>) -> Result<()> {
        let io = TokioIo::new(stream);
        
        if let Err(err) = http1::Builder::new()
            .serve_connection(io, service_fn(move |req| {
                Self::handle_proxy_request(req, Arc::clone(&request_count))
            }))
            .await
        {
            debug!("Error serving proxy connection: {:?}", err);
        }
        
        Ok(())
    }

    async fn handle_proxy_request(
        req: Request<Incoming>,
        request_count: Arc<AtomicU32>,
    ) -> Result<Response<Full<Bytes>>> {
        request_count.fetch_add(1, Ordering::Relaxed);
        
        let method = req.method().clone();
        let uri = req.uri().clone();
        
        info!(
            method = %method,
            uri = %uri,
            "Test firewall proxy received request"
        );

        // For testing purposes, we'll just forward the request using reqwest
        let (parts, body) = req.into_parts();
        let body_bytes = body.collect().await?.to_bytes();

        let client = reqwest::Client::new();
        let mut req_builder = client.request(method.clone(), uri.to_string());

        // Copy headers (skip Host header to avoid conflicts)
        for (name, value) in parts.headers.iter() {
            if name.as_str().to_lowercase() != "host" {
                req_builder = req_builder.header(name, value);
            }
        }

        req_builder = req_builder.body(body_bytes.to_vec());

        match req_builder.send().await {
            Ok(response) => {
                let status = response.status();
                let mut builder = Response::builder().status(status);

                // Copy response headers
                for (name, value) in response.headers().iter() {
                    builder = builder.header(name, value);
                }

                let response_body = response.bytes().await?;
                Ok(builder.body(Full::new(response_body))?)
            }
            Err(e) => {
                info!("Test firewall proxy failed to forward request: {}", e);
                Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Full::new(Bytes::from(format!("Proxy error: {}", e))))?)
            }
        }
    }
}
