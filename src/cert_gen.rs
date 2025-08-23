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

/// Generate a simple self-signed certificate for HTTPS proxy
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

/// Save certificate and key to files
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
}
