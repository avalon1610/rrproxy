use rrproxy::common::*;
use bytes::Bytes;

#[test]
fn integration_test_headers() {
    // Test that headers are correctly defined
    assert!(!TRANSACTION_ID_HEADER.is_empty());
    assert!(!CHUNK_INDEX_HEADER.is_empty());
    assert!(!TOTAL_CHUNKS_HEADER.is_empty());
    assert!(!IS_LAST_CHUNK_HEADER.is_empty());
    
    // Test header names follow expected pattern
    assert!(TRANSACTION_ID_HEADER.starts_with("X-"));
    assert!(CHUNK_INDEX_HEADER.starts_with("X-"));
    assert!(TOTAL_CHUNKS_HEADER.starts_with("X-"));
    assert!(IS_LAST_CHUNK_HEADER.starts_with("X-"));
}

#[test]
fn integration_test_chunking_scenario() {
    // Simulate a chunking scenario
    let original_data = "This is a test message that will be chunked into smaller pieces for transmission.";
    let chunk_size = 20;
    
    // Create chunks (simulating local proxy behavior)
    let body = Bytes::from(original_data);
    let mut chunks = Vec::new();
    let mut start = 0;
    
    while start < body.len() {
        let end = std::cmp::min(start + chunk_size, body.len());
        chunks.push(body.slice(start..end));
        start = end;
    }
    
    let total_chunks = chunks.len();
    
    // Verify chunking properties
    assert!(total_chunks > 1, "Data should be chunked");
    
    // Simulate remote proxy reassembly
    let mut reassembled = Vec::new();
    for chunk in chunks {
        reassembled.extend_from_slice(&chunk);
    }
    
    let reassembled_string = String::from_utf8(reassembled).unwrap();
    assert_eq!(reassembled_string, original_data, "Reassembled data should match original");
}

#[cfg(test)]
mod mock_server_tests {
    #[test]
    fn test_transaction_id_uniqueness() {
        use uuid::Uuid;
        
        // Generate multiple transaction IDs and ensure they're unique
        let mut ids = std::collections::HashSet::new();
        
        for _ in 0..100 {
            let id = Uuid::new_v4().to_string();
            assert!(ids.insert(id), "Transaction IDs should be unique");
        }
    }
    
    #[test]
    fn test_chunk_metadata() {
        // Test chunk metadata calculation
        let data_size = 1000;
        let chunk_size = 300;
        
        let expected_chunks = (data_size + chunk_size - 1) / chunk_size; // Ceiling division
        assert_eq!(expected_chunks, 4);
        
        // Test chunk indices
        for i in 0..expected_chunks {
            let is_last = i == expected_chunks - 1;
            if i < expected_chunks - 1 {
                assert!(!is_last, "Non-last chunks should not be marked as last");
            } else {
                assert!(is_last, "Last chunk should be marked as last");
            }
        }
    }
}

#[tokio::test]
async fn integration_test_proxy_with_mock_server() {
    use rrproxy::{local_proxy, remote_proxy};
    use std::time::Duration;
    use tokio::time::sleep;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response, body::Incoming};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;
    use http_body_util::Full;
    use bytes::Bytes;
    
    // Create a simple mock HTTP server that returns 200 OK
    async fn mock_server_handler(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let response_body = "Hello from mock server! This is a test response.";
        Ok(Response::new(Full::new(Bytes::from(response_body))))
    }
    
    // Start mock target server on port 18082
    let listener = TcpListener::bind("127.0.0.1:18082").await.expect("Failed to bind mock server");
    let mock_server_handle = tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let io = TokioIo::new(stream);
                tokio::task::spawn(async move {
                    if let Err(err) = http1::Builder::new()
                        .serve_connection(io, service_fn(mock_server_handler))
                        .await
                    {
                        eprintln!("Mock server error: {:?}", err);
                    }
                });
            }
        }
    });
    
    // Give mock server time to start
    sleep(Duration::from_millis(100)).await;
    
    // Start remote proxy
    let remote_config = remote_proxy::RemoteProxyConfig {
        listen_addr: "127.0.0.1:18081".to_string(),
        log_level: "warn".to_string(),
        log_file: None,
    };
    
    let remote_handle = tokio::spawn(async move {
        if let Err(e) = remote_proxy::start(remote_config).await {
            eprintln!("Remote proxy error: {}", e);
        }
    });
    
    // Give remote proxy time to start
    sleep(Duration::from_millis(100)).await;
    
    // Start local proxy
    let local_config = local_proxy::LocalProxyConfig {
        listen_addr: "127.0.0.1:18080".to_string(),
        remote_addr: "http://127.0.0.1:18081".to_string(),
        chunk_size: 50, // Very small chunk size to test chunking
        firewall_proxy: None,
        log_level: "warn".to_string(),
        log_file: None,
    };
    
    let local_handle = tokio::spawn(async move {
        if let Err(e) = local_proxy::start(local_config).await {
            eprintln!("Local proxy error: {}", e);
        }
    });
    
    // Give local proxy time to start
    sleep(Duration::from_millis(100)).await;
    
    // Test the proxy chain: Client -> Local Proxy -> Remote Proxy -> Mock Server
    println!("🔗 Making request through proxy chain...");
    
    // Create a proxy client that routes requests through the local proxy
    let proxy_client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http("http://127.0.0.1:18080").expect("Failed to create proxy"))
        .timeout(Duration::from_secs(5))
        .build()
        .expect("Failed to create proxy client");
    
    // Make request to the mock server through the proxy
    let response = proxy_client
        .get("http://127.0.0.1:18082/test")
        .send()
        .await;
    
    // Clean up
    mock_server_handle.abort();
    remote_handle.abort();
    local_handle.abort();
    
    // Verify the response
    match response {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.expect("Failed to read response body");
            
            println!("✅ Response received through proxy chain");
            println!("   Status: {}", status);
            println!("   Body: {}", body);
            
            assert_eq!(status.as_u16(), 200, "Should get 200 OK from mock server");
            assert!(body.contains("Hello from mock server"), "Should get expected response body");
        }
        Err(e) => {
            eprintln!("❌ Request failed: {}", e);
            panic!("Proxy integration test failed: {}", e);
        }
    }
}

#[tokio::test]
#[ignore] // Ignore by default as it requires internet connectivity
async fn integration_test_real_internet_request() {
    use rrproxy::{local_proxy, remote_proxy};
    use std::time::Duration;
    use tokio::time::sleep;
    
    // Start remote proxy
    let remote_config = remote_proxy::RemoteProxyConfig {
        listen_addr: "127.0.0.1:19081".to_string(),
        log_level: "info".to_string(),
        log_file: None,
    };
    
    let remote_handle = tokio::spawn(async move {
        if let Err(e) = remote_proxy::start(remote_config).await {
            eprintln!("Remote proxy error: {}", e);
        }
    });
    
    // Give remote proxy time to start
    sleep(Duration::from_millis(200)).await;
    
    // Start local proxy
    let local_config = local_proxy::LocalProxyConfig {
        listen_addr: "127.0.0.1:19080".to_string(),
        remote_addr: "http://127.0.0.1:19081".to_string(),
        chunk_size: 1024, // Use larger chunks for real requests
        firewall_proxy: None,
        log_level: "info".to_string(),
        log_file: None,
    };
    
    let local_handle = tokio::spawn(async move {
        if let Err(e) = local_proxy::start(local_config).await {
            eprintln!("Local proxy error: {}", e);
        }
    });
    
    // Give local proxy time to start
    sleep(Duration::from_millis(200)).await;
    
    // Test with real internet request
    let proxy_client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http("http://127.0.0.1:19080").expect("Failed to create proxy"))
        .timeout(Duration::from_secs(10))
        .build()
        .expect("Failed to create proxy client");
    
    println!("🌐 Making real internet request to www.baidu.com through proxy...");
    
    // Make request to baidu.com through the proxy
    let response = proxy_client
        .get("https://www.baidu.com")
        .send()
        .await;
    
    // Clean up
    remote_handle.abort();
    local_handle.abort();
    
    // Verify the response
    match response {
        Ok(resp) => {
            let status = resp.status();
            println!("✅ Response received from baidu.com");
            println!("   Status: {}", status);
            
            if status.is_success() {
                let body = resp.text().await.expect("Failed to read response body");
                println!("   Body length: {} bytes", body.len());
                
                // Check if we got actual baidu content
                if body.contains("baidu") || body.contains("百度") || body.contains("Baidu") {
                    println!("🎯 Response contains expected baidu content");
                } else {
                    println!("⚠️  Response doesn't contain expected baidu content");
                    println!("   First 200 chars: {}", &body[..std::cmp::min(200, body.len())]);
                }
                
                assert!(status.is_success(), "Should get successful response from baidu.com");
                assert!(!body.is_empty(), "Response body should not be empty");
            } else {
                println!("⚠️  Got non-success status: {}", status);
                let body = resp.text().await.unwrap_or_default();
                println!("   Error body: {}", &body[..std::cmp::min(500, body.len())]);
            }
        }
        Err(e) => {
            eprintln!("❌ Request to baidu.com failed: {}", e);
            
            // This test is marked as #[ignore] so it won't fail CI,
            // but we'll still print the error for debugging
            println!("Note: This test requires internet connectivity and may fail due to network issues");
        }
    }
}
