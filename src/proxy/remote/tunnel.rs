use anyhow::{anyhow, Result};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, split};
use tracing::{debug, info, error};

pub async fn handle_connect_tunnel(mut local_stream: TcpStream, request_data: String) -> Result<()> {
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
    let (mut local_read, mut local_write) = split(local_stream);
    let (mut target_read, mut target_write) = split(target_stream);
    
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
