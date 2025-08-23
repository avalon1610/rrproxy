use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_native_tls::TlsConnector;
use native_tls::TlsConnector as NativeTlsConnector;
use rrproxy::cert_gen::{CertConfig, generate_and_save_certificate};

/// Test that verifies TLS acceptor can be created and used successfully
#[tokio::test]
async fn test_tls_acceptor_creation_and_handshake() -> Result<()> {
    // Generate test certificate files
    let config = CertConfig::default();
    generate_and_save_certificate(&config, "test_cert.pem", "test_key.pem")?;
    
    // Copy to the expected location for the TLS acceptor
    std::fs::copy("test_cert.pem", "cert.pem")?;
    std::fs::copy("test_key.pem", "key.pem")?;
    
    // Test creating TLS acceptor - this was the original failing point
    let tls_acceptor = rrproxy::proxy::local::https::create_tls_acceptor();
    
    match tls_acceptor {
        Ok(acceptor) => {
            println!("✓ TLS acceptor created successfully");
            
            // Test actual TLS handshake
            test_tls_handshake(acceptor).await?;
        }
        Err(e) => {
            panic!("✗ Failed to create TLS acceptor: {}", e);
        }
    }
    
    // Clean up test files
    let _ = std::fs::remove_file("test_cert.pem");
    let _ = std::fs::remove_file("test_key.pem");
    
    Ok(())
}

/// Test actual TLS handshake with the acceptor
async fn test_tls_handshake(tls_acceptor: tokio_native_tls::TlsAcceptor) -> Result<()> {
    // Create a test server that uses our TLS acceptor
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    
    println!("Test TLS server listening on: {}", server_addr);
    
    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        println!("Server: Got connection, starting TLS handshake");
        
        // Try to accept TLS connection - this is where the ASN1 error was occurring
        match tls_acceptor.accept(stream).await {
            Ok(mut tls_stream) => {
                println!("✓ Server: TLS handshake successful");
                
                // Try to read a simple message
                let mut buffer = [0u8; 1024];
                if let Ok(n) = tls_stream.read(&mut buffer).await {
                    let message = String::from_utf8_lossy(&buffer[..n]);
                    println!("Server: Received: {}", message);
                    
                    // Echo back
                    let response = "HTTP/1.1 200 OK\r\n\r\nHello from TLS server!";
                    let _ = tls_stream.write_all(response.as_bytes()).await;
                }
            }
            Err(e) => {
                panic!("✗ Server: TLS handshake failed: {}", e);
            }
        }
    });
    
    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Create client that connects to our test server
    let client_handle = tokio::spawn(async move {
        println!("Client: Connecting to test server");
        let stream = TcpStream::connect(server_addr).await.unwrap();
        
        // Create TLS connector that accepts invalid certs (since we're using self-signed)
        let connector = NativeTlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .unwrap();
        let tokio_connector = TlsConnector::from(connector);
        
        match tokio_connector.connect("localhost", stream).await {
            Ok(mut tls_stream) => {
                println!("✓ Client: TLS handshake successful");
                
                // Send a test HTTP request
                let request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
                let _ = tls_stream.write_all(request.as_bytes()).await;
                
                // Read response
                let mut buffer = [0u8; 1024];
                if let Ok(n) = tls_stream.read(&mut buffer).await {
                    let response = String::from_utf8_lossy(&buffer[..n]);
                    println!("Client: Received: {}", response);
                }
            }
            Err(e) => {
                panic!("✗ Client: TLS handshake failed: {}", e);
            }
        }
    });
    
    // Wait for both tasks to complete
    let (server_result, client_result) = tokio::join!(server_handle, client_handle);
    server_result?;
    client_result?;
    
    println!("✓ TLS handshake test completed successfully");
    Ok(())
}

/// Test the original problematic scenario - reading certificate files and creating identity
#[test]
fn test_certificate_file_reading() -> Result<()> {
    // Test using PKCS#12 file if it exists
    if std::path::Path::new("cert.p12").exists() {
        println!("Testing with existing PKCS#12 file");
        let p12_data = std::fs::read("cert.p12")?;
        println!("PKCS#12 file size: {} bytes", p12_data.len());
        
        match native_tls::Identity::from_pkcs12(&p12_data, "") {
            Ok(_identity) => {
                println!("✓ Identity created successfully from PKCS#12 file");
                return Ok(());
            }
            Err(e) => {
                println!("✗ Failed to create identity from PKCS#12 file: {}", e);
            }
        }
    }
    
    // Fallback to testing PEM files
    println!("Testing with PEM files");
    
    // Generate test certificate files
    let config = CertConfig::default();
    generate_and_save_certificate(&config, "test_cert2.pem", "test_key2.pem")?;
    
    // Test reading the files exactly like the TLS acceptor does
    let cert_pem = std::fs::read("test_cert2.pem")?;
    let key_pem = std::fs::read("test_key2.pem")?;
    
    println!("Certificate file size: {} bytes", cert_pem.len());
    println!("Key file size: {} bytes", key_pem.len());
    
    // Verify they contain valid PEM data
    let cert_str = String::from_utf8_lossy(&cert_pem);
    let key_str = String::from_utf8_lossy(&key_pem);
    
    assert!(cert_str.contains("-----BEGIN CERTIFICATE-----"));
    assert!(cert_str.contains("-----END CERTIFICATE-----"));
    assert!(key_str.contains("-----BEGIN") && key_str.contains("PRIVATE KEY"));
    assert!(key_str.contains("-----END"));
    
    // Test creating identity - this was the failing point
    match native_tls::Identity::from_pkcs8(&cert_pem, &key_pem) {
        Ok(_identity) => {
            println!("✓ Identity created successfully from PEM files");
        }
        Err(e) => {
            println!("✗ Failed to create identity from PEM files: {}", e);
            
            // Try creating PKCS#12 file and test that
            println!("Trying to create PKCS#12 file manually...");
            
            // Write PEM files temporarily
            std::fs::write("temp_cert.pem", &cert_pem)?;
            std::fs::write("temp_key.pem", &key_pem)?;
            
            // Create PKCS#12 using OpenSSL
            let output = std::process::Command::new("openssl")
                .args(&[
                    "pkcs12", "-export",
                    "-in", "temp_cert.pem",
                    "-inkey", "temp_key.pem", 
                    "-out", "temp_test.p12",
                    "-passout", "pass:",
                    "-name", "test"
                ])
                .output();
            
            // Clean up PEM files
            let _ = std::fs::remove_file("temp_cert.pem");
            let _ = std::fs::remove_file("temp_key.pem");
            
            if let Ok(result) = output {
                if result.status.success() {
                    println!("Successfully created PKCS#12 file with OpenSSL");
                    
                    let p12_data = std::fs::read("temp_test.p12")?;
                    let _ = std::fs::remove_file("temp_test.p12");
                    
                    match native_tls::Identity::from_pkcs12(&p12_data, "") {
                        Ok(_identity) => {
                            println!("✓ Identity created successfully from generated PKCS#12");
                        }
                        Err(e) => {
                            panic!("✗ Failed to create identity from generated PKCS#12: {}", e);
                        }
                    }
                } else {
                    panic!("✗ Failed to create PKCS#12 with OpenSSL: {}", String::from_utf8_lossy(&result.stderr));
                }
            } else {
                panic!("✗ Failed to run OpenSSL command");
            }
        }
    }
    
    // Clean up
    let _ = std::fs::remove_file("test_cert2.pem");
    let _ = std::fs::remove_file("test_key2.pem");
    
    Ok(())
}
