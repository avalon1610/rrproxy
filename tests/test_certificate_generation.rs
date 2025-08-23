use rrproxy::cert_gen::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_certificate_generation_integration() {
    // Create a temporary directory for testing
    let temp_dir = TempDir::new().unwrap();
    let cert_path = temp_dir.path().join("test_cert.pem");
    let key_path = temp_dir.path().join("test_key.pem");
    
    // Test certificate generation with default config
    let config = CertConfig::default();
    let result = generate_and_save_certificate(
        &config,
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap()
    );
    
    assert!(result.is_ok(), "Certificate generation should succeed");
    
    // Verify files were created
    assert!(cert_path.exists(), "Certificate file should exist");
    assert!(key_path.exists(), "Private key file should exist");
    
    // Verify file contents
    let cert_content = fs::read_to_string(&cert_path).unwrap();
    let key_content = fs::read_to_string(&key_path).unwrap();
    
    assert!(cert_content.contains("-----BEGIN CERTIFICATE-----"));
    assert!(cert_content.contains("-----END CERTIFICATE-----"));
    assert!(key_content.contains("-----BEGIN") && key_content.contains("PRIVATE KEY"));
    
    // Test validation
    let validation_result = validate_certificate_files(
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap()
    );
    assert!(validation_result.unwrap(), "Generated certificates should be valid");
}

#[test]
fn test_certificate_generation_with_custom_config() {
    let temp_dir = TempDir::new().unwrap();
    let cert_path = temp_dir.path().join("custom_cert.pem");
    let key_path = temp_dir.path().join("custom_key.pem");
    
    // Create custom config
    let mut config = CertConfig::default();
    config.common_name = "example.com".to_string();
    config.san_domains = vec![
        "example.com".to_string(),
        "www.example.com".to_string(),
        "api.example.com".to_string(),
    ];
    config.organization = "Test Org".to_string();
    
    let result = generate_and_save_certificate(
        &config,
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap()
    );
    
    assert!(result.is_ok(), "Custom certificate generation should succeed");
    assert!(cert_path.exists(), "Custom certificate file should exist");
    assert!(key_path.exists(), "Custom private key file should exist");
}

#[test]
fn test_certificate_backup_functionality() {
    let temp_dir = TempDir::new().unwrap();
    
    // Change to temp directory for this test
    let original_dir = std::env::current_dir().unwrap();
    std::env::set_current_dir(temp_dir.path()).unwrap();
    
    let cert_path = "backup_test_cert.pem";
    let key_path = "backup_test_key.pem";
    
    // Create initial certificate files
    fs::write(cert_path, "initial certificate").unwrap();
    fs::write(key_path, "initial key").unwrap();
    
    // Generate new certificates (should trigger backup)
    let config = CertConfig::default();
    let result = generate_and_save_certificate(&config, cert_path, key_path);
    
    assert!(result.is_ok(), "Certificate generation with backup should succeed");
    
    // Check that backup directory was created
    let entries: Vec<_> = fs::read_dir(".")
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry.file_name().to_string_lossy().starts_with("cert_backup_")
        })
        .collect();
    
    assert!(!entries.is_empty(), "Backup directory should be created");
    
    // Restore original directory
    std::env::set_current_dir(original_dir).unwrap();
}

#[test] 
fn test_proxy_config_certificate_options() {
    use rrproxy::proxy::local::LocalProxyConfig;
    
    // Test default configuration
    let config = LocalProxyConfig {
        listen_addr: "127.0.0.1:8080".to_string(),
        remote_addr: "http://127.0.0.1:8081".to_string(),
        chunk_size: 1024,
        firewall_proxy: None,
        log_level: "info".to_string(),
        log_file: None,
        cert_file: "test_cert.pem".to_string(),
        key_file: "test_key.pem".to_string(),
        generate_cert: true,
        cert_common_name: Some("test.local".to_string()),
        cert_domains: Some(vec!["test.local".to_string(), "*.test.local".to_string()]),
    };
    
    assert_eq!(config.cert_file, "test_cert.pem");
    assert_eq!(config.key_file, "test_key.pem");
    assert!(config.generate_cert);
    assert_eq!(config.cert_common_name, Some("test.local".to_string()));
    assert!(config.cert_domains.is_some());
}

#[test]
fn test_certificate_validation_error_cases() {
    let temp_dir = TempDir::new().unwrap();
    let cert_path = temp_dir.path().join("invalid_cert.pem");
    let key_path = temp_dir.path().join("invalid_key.pem");
    
    // Test missing files
    let result = validate_certificate_files(
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap()
    );
    assert!(result.is_ok());
    assert!(!result.unwrap(), "Missing files should fail validation");
    
    // Test invalid certificate content
    fs::write(&cert_path, "not a certificate").unwrap();
    fs::write(&key_path, "not a private key").unwrap();
    
    let result = validate_certificate_files(
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap()
    );
    assert!(result.is_ok());
    assert!(!result.unwrap(), "Invalid certificate content should fail validation");
}

#[test]
fn test_certificate_generation_minimal_config() {
    // Test with minimal configuration - just localhost
    let _temp_dir = TempDir::new().unwrap();
    
    let config = CertConfig {
        common_name: "localhost".to_string(),
        san_domains: vec!["localhost".to_string(), "127.0.0.1".to_string()],
        organization: "Test".to_string(),
        country: "US".to_string(),
        state: "CA".to_string(),
        city: "Test".to_string(),
        org_unit: "Test".to_string(),
        validity_days: 30, // Short validity for testing
    };
    
    let result = generate_certificate(&config);
    assert!(result.is_ok(), "Minimal certificate generation should succeed");
    
    let (cert_pem, key_pem) = result.unwrap();
    
    // Basic validation
    assert!(cert_pem.contains("-----BEGIN CERTIFICATE-----"));
    assert!(cert_pem.contains("-----END CERTIFICATE-----"));
    assert!(key_pem.contains("-----BEGIN") && key_pem.contains("PRIVATE KEY"));
    assert!(cert_pem.len() > 500, "Certificate should have reasonable length");
    assert!(key_pem.len() > 200, "Private key should have reasonable length");
}
