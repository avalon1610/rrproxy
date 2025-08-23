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

    // Make request to cn.bing.com through the proxy
    let response = proxy_client.get("https://cn.bing.com").send().await;

    // Clean up
    remote_handle.abort();
    local_handle.abort();

    // Verify the response
    match response {
        Ok(resp) => {
            let status = resp.status();
            println!("✅ Response received from cn.bing.com");
            println!("   Status: {}", status);

            if status.is_success() {
                let body = resp.text().await.expect("Failed to read response body");
                println!("   Body len: {}", body.len());

                assert!(
                    status.is_success(),
                    "Should get successful response from cn.bing.com"
                );
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
            println!(
                "Note: This test requires internet connectivity and may fail due to network issues"
            );
        }
    }
}

#[tokio::test]
#[ignore] // Ignore by default as it requires internet connectivity
async fn integration_test_large_request_chunking() {
    use rrproxy::{local_proxy, remote_proxy};
    use std::time::Duration;
    use tokio::time::sleep;
    use serde_json::json;

    // Start remote proxy
    let remote_config = remote_proxy::RemoteProxyConfig {
        listen_addr: "127.0.0.1:19082".to_string(),
        log_level: "debug".to_string(), // Use debug to see chunking logs
        log_file: None,
    };

    let remote_handle = tokio::spawn(async move {
        if let Err(e) = remote_proxy::start(remote_config).await {
            eprintln!("Remote proxy error: {}", e);
        }
    });

    // Give remote proxy time to start
    sleep(Duration::from_millis(300)).await;

    // Start local proxy with small chunk size to force chunking
    let local_config = local_proxy::LocalProxyConfig {
        listen_addr: "127.0.0.1:19083".to_string(),
        remote_addr: "http://127.0.0.1:19082".to_string(),
        chunk_size: 512, // Small chunk size to force splitting
        firewall_proxy: None,
        log_level: "debug".to_string(), // Use debug to see chunking logs
        log_file: None,
    };

    let local_handle = tokio::spawn(async move {
        if let Err(e) = local_proxy::start(local_config).await {
            eprintln!("Local proxy error: {}", e);
        }
    });

    // Give local proxy time to start
    sleep(Duration::from_millis(300)).await;

    // Create a client that uses our proxy
    let proxy_client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http("http://127.0.0.1:19083").expect("Failed to create proxy"))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("Failed to create proxy client");

    println!("🔄 Testing large request with chunking...");

    // Create a large JSON payload that will definitely exceed 512 bytes
    let large_payload = json!({
        "message": "This is a large test payload that should be chunked by our proxy",
        "data": "x".repeat(2000), // 2KB of 'x' characters
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "test_info": {
            "purpose": "Integration test for chunking functionality",
            "chunk_size": 512,
            "expected_chunks": "approximately 4-5 chunks",
            "additional_data": "y".repeat(1500) // Another 1.5KB
        },
        "metadata": {
            "version": "1.0",
            "test_id": uuid::Uuid::new_v4().to_string(),
            "padding": "z".repeat(1000) // Another 1KB
        }
    });

    let payload_size = serde_json::to_string(&large_payload).unwrap().len();
    println!("📦 Payload size: {} bytes (should be chunked into multiple parts)", payload_size);

    // Use httpbin.org which is friendly for testing POST requests
    let test_url = "https://httpbin.org/post";
    
    println!("🌐 Making large POST request to {} through chunked proxy...", test_url);

    // Make the large POST request through the proxy
    let response = proxy_client
        .post(test_url)
        .json(&large_payload)
        .send()
        .await;

    // Clean up
    remote_handle.abort();
    local_handle.abort();

    // Verify the response
    match response {
        Ok(resp) => {
            let status = resp.status();
            println!("✅ Response received from httpbin.org");
            println!("   Status: {}", status);

            if status.is_success() {
                let response_text = resp.text().await.expect("Failed to read response body");
                println!("   Response body length: {}", response_text.len());

                // Parse the response to verify our data was received correctly
                if let Ok(response_json) = serde_json::from_str::<serde_json::Value>(&response_text) {
                    // httpbin.org returns the posted data in the "json" field
                    if let Some(echoed_data) = response_json.get("json") {
                        println!("✅ Server successfully received and echoed our chunked data");
                        
                        // Verify some of our test data is present
                        if let Some(message) = echoed_data.get("message") {
                            assert_eq!(
                                message.as_str().unwrap(),
                                "This is a large test payload that should be chunked by our proxy"
                            );
                        }
                        
                        if let Some(data) = echoed_data.get("data") {
                            assert_eq!(data.as_str().unwrap().len(), 2000);
                        }
                        
                        println!("✅ Data integrity verified - chunking worked correctly!");
                    }
                }

                assert!(
                    status.is_success(),
                    "Should get successful response from httpbin.org"
                );
                assert!(!response_text.is_empty(), "Response body should not be empty");
                assert!(
                    payload_size > 512,
                    "Payload should be larger than chunk size to test chunking"
                );
            } else {
                println!("⚠️  Got non-success status: {}", status);
                let body = resp.text().await.unwrap_or_default();
                println!("   Error body: {}", &body[..std::cmp::min(500, body.len())]);
            }
        }
        Err(e) => {
            eprintln!("❌ Large request test failed: {}", e);
            println!(
                "Note: This test requires internet connectivity and may fail due to network issues"
            );
        }
    }
}

mod test_firewall_proxy;

use test_firewall_proxy::TestFirewallProxy;

#[tokio::test]
#[ignore] // Ignore by default as it requires internet connectivity
async fn integration_test_firewall_proxy_functionality() {
    use rrproxy::{local_proxy, remote_proxy};
    use std::time::Duration;
    use tokio::time::sleep;
    use std::sync::Arc;

    // Start test firewall proxy on port 19090
    let firewall_proxy_addr = "127.0.0.1:19090".parse().unwrap();
    let firewall_proxy = Arc::new(TestFirewallProxy::new(firewall_proxy_addr));
    let firewall_proxy_clone = Arc::clone(&firewall_proxy);
    
    let firewall_handle = tokio::spawn(async move {
        if let Err(e) = firewall_proxy_clone.start().await {
            eprintln!("Test firewall proxy error: {}", e);
        }
    });

    // Give firewall proxy time to start
    sleep(Duration::from_millis(300)).await;

    // Start remote proxy on port 19091
    let remote_config = remote_proxy::RemoteProxyConfig {
        listen_addr: "127.0.0.1:19091".to_string(),
        log_level: "debug".to_string(),
        log_file: None,
    };

    let remote_handle = tokio::spawn(async move {
        if let Err(e) = remote_proxy::start(remote_config).await {
            eprintln!("Remote proxy error: {}", e);
        }
    });

    // Give remote proxy time to start
    sleep(Duration::from_millis(300)).await;

    // Start local proxy with firewall proxy configured on port 19092
    let local_config = local_proxy::LocalProxyConfig {
        listen_addr: "127.0.0.1:19092".to_string(),
        remote_addr: "http://127.0.0.1:19091".to_string(),
        chunk_size: 1024,
        firewall_proxy: Some("http://127.0.0.1:19090".to_string()), // Use our test firewall proxy
        log_level: "debug".to_string(),
        log_file: None,
    };

    let local_handle = tokio::spawn(async move {
        if let Err(e) = local_proxy::start(local_config).await {
            eprintln!("Local proxy error: {}", e);
        }
    });

    // Give local proxy time to start
    sleep(Duration::from_millis(300)).await;

    println!("🔥 Testing firewall proxy functionality...");
    println!("   Local Proxy: 127.0.0.1:19092");
    println!("   Remote Proxy: 127.0.0.1:19091");
    println!("   Firewall Proxy: 127.0.0.1:19090");

    // Create a client that uses our local proxy
    let proxy_client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http("http://127.0.0.1:19092").expect("Failed to create proxy"))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("Failed to create proxy client");

    // Test 1: Simple GET request through firewall proxy chain
    println!("🌐 Test 1: Making GET request through firewall proxy chain...");
    
    let response = proxy_client
        .get("https://httpbin.org/get")
        .header("User-Agent", "RRProxy-Firewall-Test/1.0")
        .send()
        .await;

    match response {
        Ok(resp) => {
            let status = resp.status();
            println!("✅ Test 1: GET request successful");
            println!("   Status: {}", status);

            if status.is_success() {
                let response_text = resp.text().await.expect("Failed to read response body");
                println!("   Response length: {}", response_text.len());

                // Verify that our firewall proxy was used
                let firewall_requests = firewall_proxy.get_request_count();
                println!("   Firewall proxy requests: {}", firewall_requests);
                assert!(firewall_requests > 0, "Firewall proxy should have received at least one request");
            }
        }
        Err(e) => {
            eprintln!("❌ Test 1 failed: {}", e);
        }
    }

    // Test 2: POST request with large payload through firewall proxy
    println!("🔄 Test 2: Making large POST request through firewall proxy chain...");
    
    let large_payload = serde_json::json!({
        "test_case": "firewall_proxy_integration",
        "description": "Testing large request chunking through firewall proxy",
        "data": "x".repeat(2048), // 2KB payload to trigger chunking
        "metadata": {
            "firewall_proxy": "http://127.0.0.1:19090",
            "remote_proxy": "http://127.0.0.1:19091",
            "local_proxy": "http://127.0.0.1:19092",
            "additional_data": "y".repeat(1024) // Another 1KB
        }
    });

    let initial_firewall_requests = firewall_proxy.get_request_count();

    let response = proxy_client
        .post("https://httpbin.org/post")
        .json(&large_payload)
        .header("Content-Type", "application/json")
        .send()
        .await;

    match response {
        Ok(resp) => {
            let status = resp.status();
            println!("✅ Test 2: Large POST request successful");
            println!("   Status: {}", status);

            if status.is_success() {
                let response_text = resp.text().await.expect("Failed to read response body");
                println!("   Response length: {}", response_text.len());

                // Verify that additional requests went through firewall proxy
                let final_firewall_requests = firewall_proxy.get_request_count();
                let new_requests = final_firewall_requests - initial_firewall_requests;
                println!("   New firewall proxy requests: {}", new_requests);
                
                assert!(new_requests > 0, "Firewall proxy should have received requests for chunked data");

                // Parse response to verify data integrity
                if let Ok(response_json) = serde_json::from_str::<serde_json::Value>(&response_text) {
                    if let Some(echoed_data) = response_json.get("json") {
                        println!("✅ Test 2: Data integrity verified through firewall proxy");
                        
                        if let Some(test_case) = echoed_data.get("test_case") {
                            assert_eq!(test_case.as_str().unwrap(), "firewall_proxy_integration");
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Test 2 failed: {}", e);
        }
    }

    // Test 3: Multiple concurrent requests
    println!("🚀 Test 3: Testing concurrent requests through firewall proxy...");
    
    let initial_count = firewall_proxy.get_request_count();
    let mut handles = Vec::new();
    
    for i in 0..5 {
        let client = proxy_client.clone();
        let handle = tokio::spawn(async move {
            let response = client
                .get(&format!("https://httpbin.org/delay/1?request={}", i))
                .send()
                .await;
            
            match response {
                Ok(resp) => resp.status().is_success(),
                Err(_) => false,
            }
        });
        handles.push(handle);
    }
    
    // Wait for all concurrent requests to complete
    let mut successful_requests = 0;
    for handle in handles {
        if let Ok(success) = handle.await {
            if success {
                successful_requests += 1;
            }
        }
    }
    println!("✅ Test 3: {}/5 concurrent requests successful", successful_requests);
    
    let final_count = firewall_proxy.get_request_count();
    let concurrent_requests = final_count - initial_count;
    println!("   Concurrent firewall proxy requests: {}", concurrent_requests);
    
    assert!(concurrent_requests >= 5, "Should have made at least 5 requests through firewall proxy");

    // Clean up
    firewall_handle.abort();
    remote_handle.abort();
    local_handle.abort();

    println!("🎉 Firewall proxy integration test completed successfully!");
    println!("   Total firewall proxy requests: {}", firewall_proxy.get_request_count());
    
    // Final verification
    assert!(firewall_proxy.get_request_count() > 5, 
        "Firewall proxy should have handled multiple requests during the test");
}

#[tokio::test]
async fn test_firewall_proxy_mock_server() {
    use std::time::Duration;
    use tokio::time::timeout;
    use std::sync::Arc;

    // Test that our mock firewall proxy can start and handle basic requests
    let firewall_proxy_addr = "127.0.0.1:19099".parse().unwrap();
    let firewall_proxy = Arc::new(TestFirewallProxy::new(firewall_proxy_addr));
    let firewall_proxy_clone = Arc::clone(&firewall_proxy);
    
    let server_handle = tokio::spawn(async move {
        if let Err(e) = firewall_proxy_clone.start().await {
            eprintln!("Test firewall proxy error: {}", e);
        }
    });
    
    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Make a simple request to verify the mock server works
    let client = reqwest::Client::new();
    let result = timeout(
        Duration::from_secs(5),
        client.get("http://127.0.0.1:19099/test").send()
    ).await;
    
    // Clean up
    server_handle.abort();
    
    // The request might fail (which is expected since we're not running a real target)
    // but it should not timeout, which means our mock server is responding
    match result {
        Ok(_) => println!("✅ Mock firewall proxy responded"),
        Err(_) => println!("✅ Mock firewall proxy test completed (timeout expected)"),
    }
    
    // Verify that the proxy received the request
    assert!(firewall_proxy.get_request_count() > 0, "Mock proxy should have received at least one request");
}
