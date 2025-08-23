use rrproxy::cert_gen::*;
use std::fs;
use tempfile::TempDir;

/// Integration test for the complete certificate generation workflow
#[test]
fn test_complete_certificate_generation_workflow() {
    let temp_dir = TempDir::new().unwrap();
    
    // Test 1: Generate self-signed certificate
    println!("=== Test 1: Self-signed certificate ===");
    let config = CertConfig {
        common_name: "localhost".to_string(),
        san_domains: vec!["localhost".to_string(), "127.0.0.1".to_string()],
        ..CertConfig::default()
    };
    
    let self_signed_mode = CertGenerationMode::SelfSigned;
    let result = generate_certificate_with_mode(&config, &self_signed_mode).unwrap();
    
    assert!(!result.server_cert_pem.is_empty());
    assert!(!result.server_key_pem.is_empty());
    assert!(result.ca_cert_pem.is_none());
    assert!(result.ca_key_pem.is_none());
    
    // Test 2: Generate root CA and server certificate
    println!("=== Test 2: Root CA + Server certificate ===");
    let generate_ca_mode = CertGenerationMode::GenerateRootCa(RootCaConfig::default());
    let ca_result = generate_certificate_with_mode(&config, &generate_ca_mode).unwrap();
    
    assert!(!ca_result.server_cert_pem.is_empty());
    assert!(!ca_result.server_key_pem.is_empty());
    assert!(ca_result.ca_cert_pem.is_some());
    assert!(ca_result.ca_key_pem.is_some());
    
    // Save CA files for next test
    let ca_cert_path = temp_dir.path().join("ca_cert.pem");
    let ca_key_path = temp_dir.path().join("ca_key.pem");
    fs::write(&ca_cert_path, ca_result.ca_cert_pem.as_ref().unwrap()).unwrap();
    fs::write(&ca_key_path, ca_result.ca_key_pem.as_ref().unwrap()).unwrap();
    
    // Test 3: Generate server certificate using existing CA
    println!("=== Test 3: Server certificate with existing CA ===");
    let existing_ca_config = RootCaConfig {
        ca_cert_path: Some(ca_cert_path.to_str().unwrap().to_string()),
        ca_key_path: Some(ca_key_path.to_str().unwrap().to_string()),
        ca_cert_config: CertConfig::default(),
    };
    let existing_ca_mode = CertGenerationMode::WithRootCa(existing_ca_config);
    
    let client_config = CertConfig {
        common_name: "client.example.com".to_string(),
        san_domains: vec!["client.example.com".to_string()],
        ..CertConfig::default()
    };
    
    let client_result = generate_certificate_with_mode(&client_config, &existing_ca_mode).unwrap();
    
    assert!(!client_result.server_cert_pem.is_empty());
    assert!(!client_result.server_key_pem.is_empty());
    assert!(client_result.ca_cert_pem.is_some());
    assert!(client_result.ca_key_pem.is_none()); // Should not return existing CA private key
    
    // Test 4: Save all certificate types
    println!("=== Test 4: Save certificate files ===");
    let server_cert_path = temp_dir.path().join("server_cert.pem");
    let server_key_path = temp_dir.path().join("server_key.pem");
    
    save_certificate_result(&ca_result, server_cert_path.to_str().unwrap(), server_key_path.to_str().unwrap(), true).unwrap();
    
    // Verify all files were created
    assert!(server_cert_path.exists());
    assert!(server_key_path.exists());
    
    let ca_cert_saved_path = format!("{}.ca.pem", server_cert_path.to_str().unwrap().trim_end_matches(".pem"));
    let ca_key_saved_path = format!("{}.ca.pem", server_key_path.to_str().unwrap().trim_end_matches(".pem"));
    assert!(std::path::Path::new(&ca_cert_saved_path).exists());
    assert!(std::path::Path::new(&ca_key_saved_path).exists());
    
    println!("✓ All certificate generation modes work correctly!");
}

/// Test certificate validation across different modes
#[test]
fn test_certificate_validation_all_modes() {
    let temp_dir = TempDir::new().unwrap();
    let config = CertConfig::default();
    
    // Test each mode and validate the generated certificates
    let modes = vec![
        ("SelfSigned", CertGenerationMode::SelfSigned),
        ("GenerateRootCa", CertGenerationMode::GenerateRootCa(RootCaConfig::default())),
    ];
    
    for (mode_name, mode) in modes {
        println!("Testing validation for mode: {}", mode_name);
        
        let result = generate_certificate_with_mode(&config, &mode).unwrap();
        
        // Save to temporary files
        let cert_path = temp_dir.path().join(format!("{}_cert.pem", mode_name.to_lowercase()));
        let key_path = temp_dir.path().join(format!("{}_key.pem", mode_name.to_lowercase()));
        
        fs::write(&cert_path, &result.server_cert_pem).unwrap();
        fs::write(&key_path, &result.server_key_pem).unwrap();
        
        // Validate the files
        let is_valid = validate_certificate_files(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap()
        ).unwrap();
        
        assert!(is_valid, "Certificate for mode {} should be valid", mode_name);
        
        // If CA files are present, validate them too
        if let Some(ref ca_cert_pem) = result.ca_cert_pem {
            if let Some(ref ca_key_pem) = result.ca_key_pem {
                let is_ca_valid = validate_ca_certificate_files(ca_cert_pem, ca_key_pem).unwrap();
                assert!(is_ca_valid, "CA certificate for mode {} should be valid", mode_name);
            }
        }
    }
}

/// Test error handling for invalid CA files
#[test]
fn test_error_handling_invalid_ca() {
    let temp_dir = TempDir::new().unwrap();
    let config = CertConfig::default();
    
    // Test with non-existent CA files
    let invalid_ca_config = RootCaConfig {
        ca_cert_path: Some("nonexistent_ca.pem".to_string()),
        ca_key_path: Some("nonexistent_ca_key.pem".to_string()),
        ca_cert_config: CertConfig::default(),
    };
    let invalid_mode = CertGenerationMode::WithRootCa(invalid_ca_config);
    
    let result = generate_certificate_with_mode(&config, &invalid_mode);
    assert!(result.is_err(), "Should fail with non-existent CA files");
    
    // Test with invalid CA file contents
    let invalid_cert_path = temp_dir.path().join("invalid_ca.pem");
    let invalid_key_path = temp_dir.path().join("invalid_ca_key.pem");
    fs::write(&invalid_cert_path, "invalid certificate content").unwrap();
    fs::write(&invalid_key_path, "invalid key content").unwrap();
    
    let invalid_content_config = RootCaConfig {
        ca_cert_path: Some(invalid_cert_path.to_str().unwrap().to_string()),
        ca_key_path: Some(invalid_key_path.to_str().unwrap().to_string()),
        ca_cert_config: CertConfig::default(),
    };
    let invalid_content_mode = CertGenerationMode::WithRootCa(invalid_content_config);
    
    let result = generate_certificate_with_mode(&config, &invalid_content_mode);
    assert!(result.is_err(), "Should fail with invalid CA file contents");
}

/// Test different certificate configurations
#[test]
fn test_different_certificate_configurations() {
    // Test with custom domain names
    let web_config = CertConfig {
        common_name: "web.example.com".to_string(),
        san_domains: vec![
            "web.example.com".to_string(),
            "www.web.example.com".to_string(),
            "api.web.example.com".to_string(),
        ],
        organization: "Example Corp".to_string(),
        country: "US".to_string(),
        state: "California".to_string(),
        city: "San Francisco".to_string(),
        org_unit: "IT Department".to_string(),
        validity_days: 90, // 3 months
    };
    
    let result = generate_certificate_with_mode(&web_config, &CertGenerationMode::SelfSigned).unwrap();
    assert!(!result.server_cert_pem.is_empty());
    assert!(!result.server_key_pem.is_empty());
    
    // Test with IP addresses
    let ip_config = CertConfig {
        common_name: "192.168.1.100".to_string(),
        san_domains: vec![
            "192.168.1.100".to_string(),
            "10.0.0.1".to_string(),
            "localhost".to_string(),
        ],
        ..CertConfig::default()
    };
    
    let result = generate_certificate_with_mode(&ip_config, &CertGenerationMode::SelfSigned).unwrap();
    assert!(!result.server_cert_pem.is_empty());
    assert!(!result.server_key_pem.is_empty());
}

/// Test the complete end-to-end certificate generation and saving workflow
#[test]
fn test_end_to_end_certificate_workflow() {
    let temp_dir = TempDir::new().unwrap();
    
    // Step 1: Generate a root CA and server certificate
    let server_config = CertConfig {
        common_name: "secure.example.com".to_string(),
        san_domains: vec!["secure.example.com".to_string(), "*.secure.example.com".to_string()],
        ..CertConfig::default()
    };
    
    let ca_mode = CertGenerationMode::GenerateRootCa(RootCaConfig {
        ca_cert_path: None,
        ca_key_path: None,
        ca_cert_config: CertConfig {
            common_name: "Example Corp Root CA".to_string(),
            organization: "Example Corp".to_string(),
            org_unit: "Security".to_string(),
            validity_days: 3650, // 10 years
            ..CertConfig::default()
        },
    });
    
    let server_cert_path = temp_dir.path().join("server.pem");
    let server_key_path = temp_dir.path().join("server_key.pem");
    
    // Generate and save using the new API
    generate_and_save_certificate_with_mode(
        &server_config,
        &ca_mode,
        server_cert_path.to_str().unwrap(),
        server_key_path.to_str().unwrap(),
    ).unwrap();
    
    // Verify server files
    assert!(server_cert_path.exists());
    assert!(server_key_path.exists());
    
    // Verify CA files were created
    let ca_cert_path = format!("{}.ca.pem", server_cert_path.to_str().unwrap().trim_end_matches(".pem"));
    let ca_key_path = format!("{}.ca.pem", server_key_path.to_str().unwrap().trim_end_matches(".pem"));
    assert!(std::path::Path::new(&ca_cert_path).exists());
    assert!(std::path::Path::new(&ca_key_path).exists());
    
    // Step 2: Use the generated CA to sign another certificate
    let client_config = CertConfig {
        common_name: "client.secure.example.com".to_string(),
        san_domains: vec!["client.secure.example.com".to_string()],
        ..CertConfig::default()
    };
    
    let existing_ca_mode = CertGenerationMode::WithRootCa(RootCaConfig {
        ca_cert_path: Some(ca_cert_path),
        ca_key_path: Some(ca_key_path),
        ca_cert_config: CertConfig::default(),
    });
    
    let client_cert_path = temp_dir.path().join("client.pem");
    let client_key_path = temp_dir.path().join("client_key.pem");
    
    generate_and_save_certificate_with_mode(
        &client_config,
        &existing_ca_mode,
        client_cert_path.to_str().unwrap(),
        client_key_path.to_str().unwrap(),
    ).unwrap();
    
    // Verify client files
    assert!(client_cert_path.exists());
    assert!(client_key_path.exists());
    
    // Step 3: Validate all generated certificates
    let server_valid = validate_certificate_files(
        server_cert_path.to_str().unwrap(),
        server_key_path.to_str().unwrap(),
    ).unwrap();
    assert!(server_valid);
    
    let client_valid = validate_certificate_files(
        client_cert_path.to_str().unwrap(),
        client_key_path.to_str().unwrap(),
    ).unwrap();
    assert!(client_valid);
    
    println!("✓ End-to-end certificate workflow completed successfully!");
}
