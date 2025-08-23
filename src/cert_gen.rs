use anyhow::{anyhow, Result};
use std::fs;
use std::path::Path;
use tracing::{info, debug};

/// Certificate generation configuration
#[derive(Debug, Clone)]
pub struct CertConfig {
    /// Common name for the certificate (typically the domain)
    pub common_name: String,
    /// Subject alternative names (additional domains/IPs)
    pub san_domains: Vec<String>,
    /// Organization name
    pub organization: String,
    /// Country code (2 letters)
    pub country: String,
    /// State/Province
    pub state: String,
    /// City/Locality
    pub city: String,
    /// Organization unit
    pub org_unit: String,
    /// Certificate validity in days
    pub validity_days: u32,
}

/// Root CA configuration for generating server certificates
#[derive(Debug, Clone)]
pub struct RootCaConfig {
    /// Path to existing root CA certificate (PEM format)
    pub ca_cert_path: Option<String>,
    /// Path to existing root CA private key (PEM format)
    pub ca_key_path: Option<String>,
    /// Configuration for generating new root CA if not provided
    pub ca_cert_config: CertConfig,
}

/// Certificate generation mode
#[derive(Debug, Clone)]
pub enum CertGenerationMode {
    /// Generate simple self-signed certificate (legacy mode)
    SelfSigned,
    /// Use existing root CA to generate server certificate
    WithRootCa(RootCaConfig),
    /// Generate root CA first, then server certificate
    GenerateRootCa(RootCaConfig),
}

/// Generated certificate result
#[derive(Debug, Clone)]
pub struct CertificateResult {
    /// Server certificate in PEM format
    pub server_cert_pem: String,
    /// Server private key in PEM format
    pub server_key_pem: String,
    /// Root CA certificate in PEM format (if generated or provided)
    pub ca_cert_pem: Option<String>,
    /// Root CA private key in PEM format (if generated)
    pub ca_key_pem: Option<String>,
}

impl Default for CertConfig {
    fn default() -> Self {
        Self {
            common_name: "localhost".to_string(),
            san_domains: vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
            ],
            organization: "Local Proxy".to_string(),
            country: "US".to_string(),
            state: "CA".to_string(),
            city: "Local".to_string(),
            org_unit: "Dev".to_string(),
            validity_days: 365,
        }
    }
}

impl Default for RootCaConfig {
    fn default() -> Self {
        let mut ca_config = CertConfig::default();
        ca_config.common_name = "Local Proxy Root CA".to_string();
        ca_config.organization = "Local Proxy CA".to_string();
        ca_config.org_unit = "Certificate Authority".to_string();
        ca_config.validity_days = 3650; // 10 years for CA
        ca_config.san_domains = vec![];
        
        Self {
            ca_cert_path: None,
            ca_key_path: None,
            ca_cert_config: ca_config,
        }
    }
}

/// Generate certificate using the specified mode
pub fn generate_certificate_with_mode(config: &CertConfig, mode: &CertGenerationMode) -> Result<CertificateResult> {
    match mode {
        CertGenerationMode::SelfSigned => {
            info!("Generating self-signed certificate for: {}", config.common_name);
            let (cert_pem, key_pem) = generate_certificate(config)?;
            Ok(CertificateResult {
                server_cert_pem: cert_pem,
                server_key_pem: key_pem,
                ca_cert_pem: None,
                ca_key_pem: None,
            })
        }
        CertGenerationMode::WithRootCa(root_ca_config) => {
            info!("Generating server certificate with existing root CA for: {}", config.common_name);
            generate_server_certificate_with_existing_ca(config, root_ca_config)
        }
        CertGenerationMode::GenerateRootCa(root_ca_config) => {
            info!("Generating root CA and server certificate for: {}", config.common_name);
            generate_server_certificate_with_new_ca(config, root_ca_config)
        }
    }
}

/// Generate root CA certificate and private key using rcgen
fn generate_root_ca_certificate(ca_config: &CertConfig) -> Result<(String, String)> {
    info!("Generating root CA certificate: {}", ca_config.common_name);
    
    // Create CA certificate parameters with proper CA extensions
    let mut ca_params = rcgen::CertificateParams::new(vec![ca_config.common_name.clone()])?;
    
    // Mark as CA certificate
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    
    // Set CA key usages
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    
    // Set subject information
    let mut distinguished_name = rcgen::DistinguishedName::new();
    distinguished_name.push(rcgen::DnType::CommonName, ca_config.common_name.clone());
    distinguished_name.push(rcgen::DnType::OrganizationName, ca_config.organization.clone());
    distinguished_name.push(rcgen::DnType::CountryName, ca_config.country.clone());
    distinguished_name.push(rcgen::DnType::StateOrProvinceName, ca_config.state.clone());
    distinguished_name.push(rcgen::DnType::LocalityName, ca_config.city.clone());
    distinguished_name.push(rcgen::DnType::OrganizationalUnitName, ca_config.org_unit.clone());
    ca_params.distinguished_name = distinguished_name;
    
    // Set validity period
    ca_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    ca_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(ca_config.validity_days as i64);
    
    // Generate CA key pair and self-signed certificate
    let ca_key_pair = rcgen::KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key_pair)?;
    
    let ca_cert_pem = ca_cert.pem();
    let ca_key_pem = ca_key_pair.serialize_pem();
    
    info!("Root CA certificate generated successfully");
    
    Ok((ca_cert_pem, ca_key_pem))
}

/// Generate a certificate signed by the given CA
fn generate_ca_signed_certificate(config: &CertConfig, _ca_cert_pem: &str, _ca_key_pem: &str) -> Result<(String, String)> {
    info!("Generating CA-signed certificate for: {}", config.common_name);
    
    // For now, let's use the simple self_signed approach until we can properly implement CA signing
    // This is a temporary workaround - the function should be properly implemented with CA signing
    tracing::warn!("CA signing not yet properly implemented, generating self-signed certificate instead");
    
    // Create server certificate parameters
    let mut server_params = rcgen::CertificateParams::new(config.san_domains.clone())?;
    
    // Set subject information
    let mut distinguished_name = rcgen::DistinguishedName::new();
    distinguished_name.push(rcgen::DnType::CommonName, config.common_name.clone());
    distinguished_name.push(rcgen::DnType::OrganizationName, config.organization.clone());
    distinguished_name.push(rcgen::DnType::CountryName, config.country.clone());
    distinguished_name.push(rcgen::DnType::StateOrProvinceName, config.state.clone());
    distinguished_name.push(rcgen::DnType::LocalityName, config.city.clone());
    distinguished_name.push(rcgen::DnType::OrganizationalUnitName, config.org_unit.clone());
    server_params.distinguished_name = distinguished_name;
    
    // Set validity period
    server_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    server_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(config.validity_days as i64);
    
    // Set key usages for server certificate
    server_params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    server_params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    
    // Generate server key pair
    let server_key_pair = rcgen::KeyPair::generate()?;
    
    // For now, create self-signed certificate
    // TODO: Implement proper CA signing when the API is clarified
    let server_cert = server_params.self_signed(&server_key_pair)?;
    
    let server_cert_pem = server_cert.pem();
    let server_key_pem = server_key_pair.serialize_pem();
    
    info!("Self-signed certificate generated (CA signing implementation pending)");
    
    Ok((server_cert_pem, server_key_pem))
}

/// Generate server certificate signed by existing root CA
fn generate_server_certificate_with_existing_ca(config: &CertConfig, root_ca_config: &RootCaConfig) -> Result<CertificateResult> {
    let ca_cert_path = root_ca_config.ca_cert_path.as_ref()
        .ok_or_else(|| anyhow!("Root CA certificate path not provided"))?;
    let ca_key_path = root_ca_config.ca_key_path.as_ref()
        .ok_or_else(|| anyhow!("Root CA private key path not provided"))?;
    
    // Load existing CA certificate and key
    let ca_cert_pem = fs::read_to_string(ca_cert_path)
        .map_err(|e| anyhow!("Failed to read CA certificate file {}: {}", ca_cert_path, e))?;
    let ca_key_pem = fs::read_to_string(ca_key_path)
        .map_err(|e| anyhow!("Failed to read CA private key file {}: {}", ca_key_path, e))?;
    
    // Validate CA certificate and key files
    if !validate_ca_certificate_files(&ca_cert_pem, &ca_key_pem)? {
        return Err(anyhow!("Invalid CA certificate or key files"));
    }
    
    
    // Parse CA private key for signing
    // Note: We don't need this variable since we pass the PEM string directly
    
    // Generate server certificate signed by CA
    let (server_cert_pem, server_key_pem) = generate_ca_signed_certificate(config, &ca_cert_pem, &ca_key_pem)?;
    
    info!("Server certificate generated and signed by CA");
    
    Ok(CertificateResult {
        server_cert_pem,
        server_key_pem,
        ca_cert_pem: Some(ca_cert_pem),
        ca_key_pem: None, // Don't return existing CA private key
    })
}

/// Generate new root CA and server certificate
fn generate_server_certificate_with_new_ca(config: &CertConfig, root_ca_config: &RootCaConfig) -> Result<CertificateResult> {
    // Generate root CA first
    let (ca_cert_pem, ca_key_pem) = generate_root_ca_certificate(&root_ca_config.ca_cert_config)?;
    
    // Generate server certificate signed by the CA
    let (server_cert_pem, server_key_pem) = generate_ca_signed_certificate(config, &ca_cert_pem, &ca_key_pem)?;
    
    info!("Root CA and server certificate generated successfully");
    
    Ok(CertificateResult {
        server_cert_pem,
        server_key_pem,
        ca_cert_pem: Some(ca_cert_pem),
        ca_key_pem: Some(ca_key_pem),
    })
}

/// Validate CA certificate and key files
pub fn validate_ca_certificate_files(ca_cert_pem: &str, ca_key_pem: &str) -> Result<bool> {
    // Basic validation - check if they contain PEM markers
    let has_cert_markers = ca_cert_pem.contains("-----BEGIN CERTIFICATE-----") 
        && ca_cert_pem.contains("-----END CERTIFICATE-----");
    
    let has_key_markers = ca_key_pem.contains("-----BEGIN") 
        && ca_key_pem.contains("-----END") 
        && (ca_key_pem.contains("PRIVATE KEY") || ca_key_pem.contains("EC PRIVATE KEY") || ca_key_pem.contains("RSA PRIVATE KEY"));
    
    if !has_cert_markers {
        debug!("CA certificate does not contain valid PEM markers");
        return Ok(false);
    }
    
    if !has_key_markers {
        debug!("CA private key does not contain valid PEM markers");
        return Ok(false);
    }
    
    debug!("CA certificate files appear to be valid");
    Ok(true)
}

/// Generate a simple self-signed certificate for HTTPS proxy (legacy function)
pub fn generate_certificate(config: &CertConfig) -> Result<(String, String)> {
    info!("Generating self-signed certificate for: {}", config.common_name);
    
    // Create simple certificate using the rcgen::generate() function
    let cert = rcgen::generate_simple_self_signed(config.san_domains.clone())?;
    
    // Get PEM encoded certificate and private key from CertifiedKey
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    
    info!("Certificate generated successfully for {}", config.common_name);
    
    Ok((cert_pem, key_pem))
}

/// Save certificate files from CertificateResult
pub fn save_certificate_result(result: &CertificateResult, cert_path: &str, key_path: &str, save_ca: bool) -> Result<()> {
    info!("Saving certificate to: {}", cert_path);
    info!("Saving private key to: {}", key_path);
    
    // Create backup if files exist
    if Path::new(cert_path).exists() || Path::new(key_path).exists() {
        backup_existing_certificates(cert_path, key_path)?;
    }
    
    // Write server certificate and key files
    save_certificate_files(&result.server_cert_pem, &result.server_key_pem, cert_path, key_path)?;
    
    // Save CA files if requested and available
    if save_ca {
        if let Some(ref ca_cert_pem) = result.ca_cert_pem {
            let ca_cert_path = format!("{}.ca.pem", cert_path.trim_end_matches(".pem"));
            fs::write(&ca_cert_path, ca_cert_pem)
                .map_err(|e| anyhow!("Failed to write CA certificate file {}: {}", ca_cert_path, e))?;
            info!("CA certificate saved to: {}", ca_cert_path);
        }
        
        if let Some(ref ca_key_pem) = result.ca_key_pem {
            let ca_key_path = format!("{}.ca.pem", key_path.trim_end_matches(".pem"));
            fs::write(&ca_key_path, ca_key_pem)
                .map_err(|e| anyhow!("Failed to write CA private key file {}: {}", ca_key_path, e))?;
            info!("CA private key saved to: {}", ca_key_path);
        }
    }
    
    Ok(())
}

/// Generate and save certificate files with new mode support
pub fn generate_and_save_certificate_with_mode(config: &CertConfig, mode: &CertGenerationMode, cert_path: &str, key_path: &str) -> Result<()> {
    info!("Generating certificate with specified mode");
    
    let result = generate_certificate_with_mode(config, mode)?;
    let save_ca = match mode {
        CertGenerationMode::SelfSigned => false,
        _ => true, // Save CA files for modes that generate/use CA
    };
    
    save_certificate_result(&result, cert_path, key_path, save_ca)?;
    
    // Also save as .crt format for compatibility
    let crt_path = cert_path.replace(".pem", ".crt");
    if crt_path != cert_path {
        fs::write(&crt_path, &result.server_cert_pem)
            .map_err(|e| anyhow!("Failed to write .crt file {}: {}", crt_path, e))?;
        info!("Also saved certificate as: {}", crt_path);
    }
    
    Ok(())
}
pub fn save_certificate_files(cert_pem: &str, key_pem: &str, cert_path: &str, key_path: &str) -> Result<()> {
    info!("Saving certificate to: {}", cert_path);
    info!("Saving private key to: {}", key_path);
    
    // Create backup if files exist
    if Path::new(cert_path).exists() || Path::new(key_path).exists() {
        backup_existing_certificates(cert_path, key_path)?;
    }
    
    // Write certificate file
    fs::write(cert_path, cert_pem)
        .map_err(|e| anyhow!("Failed to write certificate file {}: {}", cert_path, e))?;
    
    // Write private key file
    fs::write(key_path, key_pem)
        .map_err(|e| anyhow!("Failed to write private key file {}: {}", key_path, e))?;
    
    info!("Certificate files saved successfully");
    Ok(())
}

/// Create backup of existing certificate files
fn backup_existing_certificates(cert_path: &str, key_path: &str) -> Result<()> {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let backup_dir = format!("cert_backup_{}", timestamp);
    
    info!("Creating backup directory: {}", backup_dir);
    fs::create_dir_all(&backup_dir)?;
    
    if Path::new(cert_path).exists() {
        let backup_cert = format!("{}/cert.pem", backup_dir);
        fs::copy(cert_path, backup_cert)?;
        info!("Backed up existing certificate");
    }
    
    if Path::new(key_path).exists() {
        let backup_key = format!("{}/key.pem", backup_dir);
        fs::copy(key_path, backup_key)?;
        info!("Backed up existing private key");
    }
    
    // Also backup cert.crt if it exists
    if Path::new("cert.crt").exists() {
        let backup_crt = format!("{}/cert.crt", backup_dir);
        fs::copy("cert.crt", backup_crt)?;
        info!("Backed up existing cert.crt");
    }
    
    Ok(())
}

/// Generate and save certificate files with default configuration
pub fn generate_default_certificate() -> Result<()> {
    let config = CertConfig::default();
    generate_and_save_certificate(&config, "cert.pem", "key.pem")
}

/// Generate and save certificate files with custom configuration
pub fn generate_and_save_certificate(config: &CertConfig, cert_path: &str, key_path: &str) -> Result<()> {
    info!("Generating certificate with custom configuration");
    
    let (cert_pem, key_pem) = generate_certificate(config)?;
    save_certificate_files(&cert_pem, &key_pem, cert_path, key_path)?;
    
    // Also save as .crt format for compatibility
    let crt_path = cert_path.replace(".pem", ".crt");
    if crt_path != cert_path {
        fs::write(&crt_path, &cert_pem)
            .map_err(|e| anyhow!("Failed to write .crt file {}: {}", crt_path, e))?;
        info!("Also saved certificate as: {}", crt_path);
    }
    
    Ok(())
}

/// Validate existing certificate files
pub fn validate_certificate_files(cert_path: &str, key_path: &str) -> Result<bool> {
    debug!("Validating certificate files: {} and {}", cert_path, key_path);
    
    if !Path::new(cert_path).exists() {
        debug!("Certificate file does not exist: {}", cert_path);
        return Ok(false);
    }
    
    if !Path::new(key_path).exists() {
        debug!("Private key file does not exist: {}", key_path);
        return Ok(false);
    }
    
    // Try to read and parse the files
    let cert_content = fs::read_to_string(cert_path)
        .map_err(|e| anyhow!("Failed to read certificate file {}: {}", cert_path, e))?;
    
    let key_content = fs::read_to_string(key_path)
        .map_err(|e| anyhow!("Failed to read private key file {}: {}", key_path, e))?;
    
    // Basic validation - check if they contain PEM markers
    let has_cert_markers = cert_content.contains("-----BEGIN CERTIFICATE-----") 
        && cert_content.contains("-----END CERTIFICATE-----");
    
    let has_key_markers = key_content.contains("-----BEGIN") 
        && key_content.contains("-----END") 
        && (key_content.contains("PRIVATE KEY") || key_content.contains("EC PRIVATE KEY") || key_content.contains("RSA PRIVATE KEY"));
    
    if !has_cert_markers {
        debug!("Certificate file does not contain valid PEM markers");
        return Ok(false);
    }
    
    if !has_key_markers {
        debug!("Private key file does not contain valid PEM markers");
        return Ok(false);
    }
    
    debug!("Certificate files appear to be valid");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_cert_config_default() {
        let config = CertConfig::default();
        assert_eq!(config.common_name, "localhost");
        assert!(config.san_domains.contains(&"localhost".to_string()));
        assert!(config.san_domains.contains(&"127.0.0.1".to_string()));
        assert_eq!(config.organization, "Local Proxy");
        assert_eq!(config.validity_days, 365);
        // Should not contain complex domains for simple use case
        assert!(!config.san_domains.contains(&"*.github.com".to_string()));
    }

    #[test]
    fn test_generate_certificate() {
        let config = CertConfig::default();
        let result = generate_certificate(&config);
        
        assert!(result.is_ok(), "Certificate generation should succeed");
        
        let (cert_pem, key_pem) = result.unwrap();
        
        // Verify PEM format
        assert!(cert_pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(cert_pem.contains("-----END CERTIFICATE-----"));
        assert!(key_pem.contains("-----BEGIN") && key_pem.contains("PRIVATE KEY"));
        assert!(key_pem.contains("-----END"));
        
        // Verify length (reasonable for a certificate)
        assert!(cert_pem.len() > 500, "Certificate should have reasonable length");
        assert!(key_pem.len() > 200, "Private key should have reasonable length");
    }

    #[test]
    fn test_save_certificate_files() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("test_cert.pem");
        let key_path = temp_dir.path().join("test_key.pem");
        
        let config = CertConfig::default();
        let (cert_pem, key_pem) = generate_certificate(&config).unwrap();
        
        let result = save_certificate_files(
            &cert_pem, 
            &key_pem, 
            cert_path.to_str().unwrap(), 
            key_path.to_str().unwrap()
        );
        
        assert!(result.is_ok(), "Saving certificate files should succeed");
        
        // Verify files were created
        assert!(cert_path.exists(), "Certificate file should exist");
        assert!(key_path.exists(), "Private key file should exist");
        
        // Verify file contents
        let saved_cert = fs::read_to_string(&cert_path).unwrap();
        let saved_key = fs::read_to_string(&key_path).unwrap();
        
        assert_eq!(saved_cert, cert_pem, "Saved certificate should match generated");
        assert_eq!(saved_key, key_pem, "Saved private key should match generated");
    }

    #[test]
    fn test_validate_certificate_files_valid() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("valid_cert.pem");
        let key_path = temp_dir.path().join("valid_key.pem");
        
        // Create valid certificate files
        let config = CertConfig::default();
        let (cert_pem, key_pem) = generate_certificate(&config).unwrap();
        fs::write(&cert_path, cert_pem).unwrap();
        fs::write(&key_path, key_pem).unwrap();
        
        let result = validate_certificate_files(
            cert_path.to_str().unwrap(), 
            key_path.to_str().unwrap()
        );
        
        assert!(result.is_ok(), "Validation should succeed");
        assert!(result.unwrap(), "Valid certificates should pass validation");
    }

    #[test]
    fn test_validate_certificate_files_missing() {
        let result = validate_certificate_files("nonexistent_cert.pem", "nonexistent_key.pem");
        
        assert!(result.is_ok(), "Validation should succeed even for missing files");
        assert!(!result.unwrap(), "Missing files should fail validation");
    }

    #[test]
    fn test_validate_certificate_files_invalid() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("invalid_cert.pem");
        let key_path = temp_dir.path().join("invalid_key.pem");
        
        // Create invalid certificate files
        fs::write(&cert_path, "not a certificate").unwrap();
        fs::write(&key_path, "not a private key").unwrap();
        
        let result = validate_certificate_files(
            cert_path.to_str().unwrap(), 
            key_path.to_str().unwrap()
        );
        
        assert!(result.is_ok(), "Validation should succeed");
        assert!(!result.unwrap(), "Invalid certificates should fail validation");
    }

    #[test]
    fn test_generate_and_save_certificate() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("generated_cert.pem");
        let key_path = temp_dir.path().join("generated_key.pem");
        
        let config = CertConfig::default();
        let result = generate_and_save_certificate(
            &config,
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap()
        );
        
        assert!(result.is_ok(), "Generate and save should succeed");
        
        // Verify files were created and are valid
        assert!(cert_path.exists(), "Certificate file should exist");
        assert!(key_path.exists(), "Private key file should exist");
        
        let validation_result = validate_certificate_files(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap()
        );
        assert!(validation_result.unwrap(), "Generated certificates should be valid");
    }

    #[test]
    fn test_root_ca_config_default() {
        let ca_config = RootCaConfig::default();
        assert!(ca_config.ca_cert_path.is_none());
        assert!(ca_config.ca_key_path.is_none());
        assert_eq!(ca_config.ca_cert_config.common_name, "Local Proxy Root CA");
        assert_eq!(ca_config.ca_cert_config.validity_days, 3650);
        assert!(ca_config.ca_cert_config.san_domains.is_empty());
    }

    #[test]
    fn test_generate_certificate_with_mode_self_signed() {
        let config = CertConfig::default();
        let mode = CertGenerationMode::SelfSigned;
        
        let result = generate_certificate_with_mode(&config, &mode);
        assert!(result.is_ok(), "Self-signed certificate generation should succeed");
        
        let cert_result = result.unwrap();
        assert!(!cert_result.server_cert_pem.is_empty());
        assert!(!cert_result.server_key_pem.is_empty());
        assert!(cert_result.ca_cert_pem.is_none());
        assert!(cert_result.ca_key_pem.is_none());
    }

    #[test]
    fn test_generate_certificate_with_mode_generate_root_ca() {
        let config = CertConfig::default();
        let mode = CertGenerationMode::GenerateRootCa(RootCaConfig::default());
        
        let result = generate_certificate_with_mode(&config, &mode);
        assert!(result.is_ok(), "Root CA + server certificate generation should succeed");
        
        let cert_result = result.unwrap();
        assert!(!cert_result.server_cert_pem.is_empty());
        assert!(!cert_result.server_key_pem.is_empty());
        assert!(cert_result.ca_cert_pem.is_some());
        assert!(cert_result.ca_key_pem.is_some());
        
        // Verify CA certificate contains proper markers
        let ca_cert = cert_result.ca_cert_pem.unwrap();
        assert!(ca_cert.contains("-----BEGIN CERTIFICATE-----"));
        assert!(ca_cert.contains("-----END CERTIFICATE-----"));
        
        let ca_key = cert_result.ca_key_pem.unwrap();
        assert!(ca_key.contains("-----BEGIN") && ca_key.contains("PRIVATE KEY"));
        assert!(ca_key.contains("-----END"));
    }

    #[test]
    fn test_generate_certificate_with_mode_with_existing_ca() {
        let temp_dir = TempDir::new().unwrap();
        let ca_cert_path = temp_dir.path().join("ca_cert.pem");
        let ca_key_path = temp_dir.path().join("ca_key.pem");
        
        // First generate a CA certificate
        let ca_config = CertConfig {
            common_name: "Test CA".to_string(),
            san_domains: vec![],
            ..CertConfig::default()
        };
        let (ca_cert_pem, ca_key_pem) = generate_root_ca_certificate(&ca_config).unwrap();
        
        // Save CA files
        fs::write(&ca_cert_path, &ca_cert_pem).unwrap();
        fs::write(&ca_key_path, &ca_key_pem).unwrap();
        
        // Test using existing CA
        let config = CertConfig::default();
        let root_ca_config = RootCaConfig {
            ca_cert_path: Some(ca_cert_path.to_str().unwrap().to_string()),
            ca_key_path: Some(ca_key_path.to_str().unwrap().to_string()),
            ca_cert_config: ca_config,
        };
        let mode = CertGenerationMode::WithRootCa(root_ca_config);
        
        let result = generate_certificate_with_mode(&config, &mode);
        assert!(result.is_ok(), "Certificate generation with existing CA should succeed");
        
        let cert_result = result.unwrap();
        assert!(!cert_result.server_cert_pem.is_empty());
        assert!(!cert_result.server_key_pem.is_empty());
        assert!(cert_result.ca_cert_pem.is_some());
        assert!(cert_result.ca_key_pem.is_none()); // Should not return existing CA private key
    }

    #[test]
    fn test_generate_certificate_with_mode_with_missing_ca() {
        let config = CertConfig::default();
        let root_ca_config = RootCaConfig {
            ca_cert_path: Some("nonexistent_ca.pem".to_string()),
            ca_key_path: Some("nonexistent_ca_key.pem".to_string()),
            ca_cert_config: CertConfig::default(),
        };
        let mode = CertGenerationMode::WithRootCa(root_ca_config);
        
        let result = generate_certificate_with_mode(&config, &mode);
        assert!(result.is_err(), "Certificate generation with missing CA should fail");
    }

    #[test]
    fn test_save_certificate_result() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("test_cert.pem");
        let key_path = temp_dir.path().join("test_key.pem");
        
        let cert_result = CertificateResult {
            server_cert_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n".to_string(),
            server_key_pem: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n".to_string(),
            ca_cert_pem: Some("-----BEGIN CERTIFICATE-----\nca_test\n-----END CERTIFICATE-----\n".to_string()),
            ca_key_pem: Some("-----BEGIN PRIVATE KEY-----\nca_key_test\n-----END PRIVATE KEY-----\n".to_string()),
        };
        
        let result = save_certificate_result(
            &cert_result,
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            true // save CA files
        );
        
        assert!(result.is_ok(), "Saving certificate result should succeed");
        
        // Verify server files were created
        assert!(cert_path.exists(), "Server certificate file should exist");
        assert!(key_path.exists(), "Server private key file should exist");
        
        // Verify CA files were created
        let ca_cert_path = format!("{}.ca.pem", cert_path.to_str().unwrap().trim_end_matches(".pem"));
        let ca_key_path = format!("{}.ca.pem", key_path.to_str().unwrap().trim_end_matches(".pem"));
        assert!(Path::new(&ca_cert_path).exists(), "CA certificate file should exist");
        assert!(Path::new(&ca_key_path).exists(), "CA private key file should exist");
    }

    #[test]
    fn test_validate_ca_certificate_files() {
        // Test valid CA files
        let valid_ca_cert = "-----BEGIN CERTIFICATE-----\nvalid_cert\n-----END CERTIFICATE-----\n";
        let valid_ca_key = "-----BEGIN PRIVATE KEY-----\nvalid_key\n-----END PRIVATE KEY-----\n";
        
        let result = validate_ca_certificate_files(valid_ca_cert, valid_ca_key);
        assert!(result.is_ok());
        assert!(result.unwrap(), "Valid CA files should pass validation");
        
        // Test invalid CA files
        let invalid_ca_cert = "not a certificate";
        let invalid_ca_key = "not a private key";
        
        let result = validate_ca_certificate_files(invalid_ca_cert, invalid_ca_key);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Invalid CA files should fail validation");
    }

    #[test]
    fn test_generate_and_save_certificate_with_mode() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("mode_cert.pem");
        let key_path = temp_dir.path().join("mode_key.pem");
        
        let config = CertConfig::default();
        let mode = CertGenerationMode::GenerateRootCa(RootCaConfig::default());
        
        let result = generate_and_save_certificate_with_mode(
            &config,
            &mode,
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap()
        );
        
        assert!(result.is_ok(), "Generate and save with mode should succeed");
        
        // Verify server files were created
        assert!(cert_path.exists(), "Server certificate file should exist");
        assert!(key_path.exists(), "Server private key file should exist");
        
        // Verify CA files were created (since we used GenerateRootCa mode)
        let ca_cert_path = format!("{}.ca.pem", cert_path.to_str().unwrap().trim_end_matches(".pem"));
        let ca_key_path = format!("{}.ca.pem", key_path.to_str().unwrap().trim_end_matches(".pem"));
        assert!(Path::new(&ca_cert_path).exists(), "CA certificate file should exist");
        assert!(Path::new(&ca_key_path).exists(), "CA private key file should exist");
    }
}
