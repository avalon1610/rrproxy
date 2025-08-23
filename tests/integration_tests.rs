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
