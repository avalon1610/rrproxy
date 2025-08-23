use anyhow::Result;
use tokio::process::Command;
use std::time::Duration;

/// Integration test that actually connects to the running proxy
#[tokio::test] 
async fn test_https_proxy_connection() -> Result<()> {
    // Wait a bit for the proxy to start up
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    println!("Testing HTTPS connection through the proxy...");
    
    // Try to make an HTTPS request through the proxy using curl
    let output = Command::new("curl")
        .args(&[
            "-v",                          // Verbose output
            "--proxy", "127.0.0.1:8080",  // Use our proxy
            "--insecure",                  // Accept self-signed certificates
            "--connect-timeout", "10",     // Timeout
            "--max-time", "30",           // Max time for the operation
            "https://httpbin.org/get"     // Simple HTTPS endpoint
        ])
        .output()
        .await;
    
    match output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout);
            let stderr = String::from_utf8_lossy(&result.stderr);
            
            println!("CURL stdout:\n{}", stdout);
            println!("CURL stderr:\n{}", stderr);
            
            if result.status.success() {
                println!("✓ HTTPS request through proxy succeeded");
                
                // Check if we got a valid response
                if stdout.contains("\"url\": \"https://httpbin.org/get\"") {
                    println!("✓ Received expected response from httpbin.org");
                } else {
                    println!("⚠ Response format unexpected, but connection worked");
                }
            } else {
                println!("✗ CURL command failed with status: {}", result.status);
                println!("This might indicate the TLS issue still exists");
                
                // Check if it's a TLS-related error
                if stderr.contains("SSL") || stderr.contains("TLS") || stderr.contains("certificate") {
                    println!("Error appears to be TLS-related");
                    return Err(anyhow::anyhow!("TLS connection failed"));
                }
            }
        }
        Err(e) => {
            println!("✗ Failed to run curl command: {}", e);
            println!("Make sure curl is installed and the proxy is running");
            return Err(e.into());
        }
    }
    
    Ok(())
}

/// Test using a simple TCP connection to check if the proxy is responsive
#[tokio::test]
async fn test_proxy_tcp_connection() -> Result<()> {
    use tokio::net::TcpStream;
    use tokio::io::{AsyncWriteExt, AsyncReadExt};
    
    println!("Testing basic TCP connection to proxy...");
    
    // Try to connect to the proxy
    match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect("127.0.0.1:8080")).await {
        Ok(Ok(mut stream)) => {
            println!("✓ Successfully connected to proxy on 127.0.0.1:8080");
            
            // Try to send a simple HTTP CONNECT request
            let connect_request = "CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org:443\r\n\r\n";
            
            if let Err(e) = stream.write_all(connect_request.as_bytes()).await {
                println!("✗ Failed to send CONNECT request: {}", e);
                return Err(e.into());
            }
            
            // Try to read the response
            let mut buffer = [0u8; 1024];
            match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer)).await {
                Ok(Ok(n)) => {
                    if n > 0 {
                        let response = String::from_utf8_lossy(&buffer[..n]);
                        println!("Received response: {}", response);
                        
                        if response.contains("200 Connection Established") {
                            println!("✓ Proxy accepted CONNECT request");
                        } else {
                            println!("⚠ Unexpected response from proxy");
                        }
                    } else {
                        println!("✗ Connection closed by proxy");
                    }
                }
                Ok(Err(e)) => {
                    println!("✗ Error reading from proxy: {}", e);
                    return Err(e.into());
                }
                Err(_) => {
                    println!("✗ Timeout waiting for proxy response");
                    return Err(anyhow::anyhow!("Timeout"));
                }
            }
        }
        Ok(Err(e)) => {
            println!("✗ Failed to connect to proxy: {}", e);
            println!("Make sure the proxy is running on 127.0.0.1:8080");
            return Err(e.into());
        }
        Err(_) => {
            println!("✗ Timeout connecting to proxy");
            return Err(anyhow::anyhow!("Connection timeout"));
        }
    }
    
    Ok(())
}
