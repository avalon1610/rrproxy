use crate::cert_gen::CertConfig;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

/// Certificate cache entry containing certificate and private key
#[derive(Debug, Clone)]
pub struct CachedCertificate {
    pub cert_pem: String,
    pub key_pem: String,
    pub created_at: std::time::SystemTime,
}

/// Dynamic certificate manager that generates and caches certificates on-demand
#[derive(Debug)]
pub struct DynamicCertificateManager {
    cache_dir: PathBuf,
    ca_cert_pem: String,
    ca_key_pem: String,
    memory_cache: Arc<RwLock<HashMap<String, CachedCertificate>>>,
}

impl DynamicCertificateManager {
    /// Create a new dynamic certificate manager
    pub fn new(cache_dir: &str, ca_cert_path: &str, ca_key_path: &str) -> Result<Self> {
        // Create cache directory if it doesn't exist
        let cache_path = PathBuf::from(cache_dir);
        if !cache_path.exists() {
            fs::create_dir_all(&cache_path)?;
            info!("Created certificate cache directory: {}", cache_dir);
        }

        // Load root CA certificate and key
        let ca_cert_pem = fs::read_to_string(ca_cert_path)
            .map_err(|e| anyhow!("Failed to read CA certificate {}: {}", ca_cert_path, e))?;
        let ca_key_pem = fs::read_to_string(ca_key_path)
            .map_err(|e| anyhow!("Failed to read CA private key {}: {}", ca_key_path, e))?;

        // Validate CA files
        if !validate_ca_files(&ca_cert_pem, &ca_key_pem)? {
            return Err(anyhow!("Invalid CA certificate or key files"));
        }

        info!(
            "Dynamic certificate manager initialized with cache dir: {}",
            cache_dir
        );

        Ok(Self {
            cache_dir: cache_path,
            ca_cert_pem,
            ca_key_pem,
            memory_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Get or generate a certificate for the given hostname
    pub fn get_certificate_for_host(&self, hostname: &str) -> Result<CachedCertificate> {
        let cache_key = self.normalize_hostname(hostname);

        // First check memory cache
        if let Some(cached_cert) = self.get_from_memory_cache(&cache_key) {
            debug!("Found certificate in memory cache for: {}", hostname);
            return Ok(cached_cert);
        }

        // Then check disk cache
        if let Some(cached_cert) = self.get_from_disk_cache(&cache_key)? {
            debug!("Found certificate in disk cache for: {}", hostname);
            // Store in memory cache for faster future access
            self.store_in_memory_cache(&cache_key, &cached_cert);
            return Ok(cached_cert);
        }

        // Generate new certificate
        info!("Generating new certificate for: {}", hostname);
        let cert = self.generate_certificate_for_host(&cache_key, hostname)?;

        // Store in both caches
        self.store_in_disk_cache(&cache_key, &cert)?;
        self.store_in_memory_cache(&cache_key, &cert);

        Ok(cert)
    }

    /// Normalize hostname for use as cache key
    fn normalize_hostname(&self, hostname: &str) -> String {
        // Convert to lowercase and remove port if present
        let host = hostname.split(':').next().unwrap_or(hostname);
        host.to_lowercase()
    }

    /// Check memory cache for certificate
    fn get_from_memory_cache(&self, cache_key: &str) -> Option<CachedCertificate> {
        let cache = self.memory_cache.read().ok()?;
        cache.get(cache_key).cloned()
    }

    /// Store certificate in memory cache
    fn store_in_memory_cache(&self, cache_key: &str, cert: &CachedCertificate) {
        if let Ok(mut cache) = self.memory_cache.write() {
            cache.insert(cache_key.to_string(), cert.clone());
        }
    }

    /// Check disk cache for certificate
    fn get_from_disk_cache(&self, cache_key: &str) -> Result<Option<CachedCertificate>> {
        let cert_path = self.cache_dir.join(format!("{}.cert.pem", cache_key));
        let key_path = self.cache_dir.join(format!("{}.key.pem", cache_key));

        if !cert_path.exists() || !key_path.exists() {
            return Ok(None);
        }

        let cert_pem = fs::read_to_string(&cert_path).map_err(|e| {
            anyhow!(
                "Failed to read cached certificate {}: {}",
                cert_path.display(),
                e
            )
        })?;
        let key_pem = fs::read_to_string(&key_path).map_err(|e| {
            anyhow!(
                "Failed to read cached private key {}: {}",
                key_path.display(),
                e
            )
        })?;

        // Get file creation time
        let created_at = cert_path
            .metadata()
            .and_then(|m| m.created())
            .unwrap_or_else(|_| std::time::SystemTime::now());

        Ok(Some(CachedCertificate {
            cert_pem,
            key_pem,
            created_at,
        }))
    }

    /// Store certificate in disk cache
    fn store_in_disk_cache(&self, cache_key: &str, cert: &CachedCertificate) -> Result<()> {
        let cert_path = self.cache_dir.join(format!("{}.cert.pem", cache_key));
        let key_path = self.cache_dir.join(format!("{}.key.pem", cache_key));

        fs::write(&cert_path, &cert.cert_pem).map_err(|e| {
            anyhow!(
                "Failed to write cached certificate {}: {}",
                cert_path.display(),
                e
            )
        })?;
        fs::write(&key_path, &cert.key_pem).map_err(|e| {
            anyhow!(
                "Failed to write cached private key {}: {}",
                key_path.display(),
                e
            )
        })?;

        debug!("Stored certificate in disk cache: {}", cache_key);
        Ok(())
    }

    /// Generate a new certificate for the given hostname using the root CA
    fn generate_certificate_for_host(
        &self,
        _cache_key: &str,
        hostname: &str,
    ) -> Result<CachedCertificate> {
        // Create certificate configuration for this hostname
        let mut cert_config = CertConfig {
            common_name: hostname.to_string(),
            san_domains: vec![hostname.to_string()],
            ..Default::default()
        };

        // Add www variant if it's a domain (not an IP)
        if hostname.parse::<std::net::IpAddr>().is_err() && !hostname.starts_with("www.") {
            cert_config.san_domains.push(format!("www.{}", hostname));
        }

        // Generate certificate using our CA (for now, simplified as self-signed)
        // TODO: In a full implementation, this would use the actual CA to sign the certificate
        // Generate certificate signed by the loaded CA
        let result = self.generate_certificate_with_ca(&cert_config)?;

        Ok(CachedCertificate {
            cert_pem: result.0,
            key_pem: result.1,
            created_at: std::time::SystemTime::now(),
        })
    }

    /// Generate certificate using the root CA
    fn generate_certificate_with_ca(&self, config: &CertConfig) -> Result<(String, String)> {
        debug!(
            "Generating CA-signed certificate for domains: {:?}",
            config.san_domains
        );

        // Use the CA-aware certificate generation from cert_gen module
        crate::cert_gen::generate_ca_signed_certificate(config, &self.ca_cert_pem, &self.ca_key_pem)
    }

    /// Clear old certificates from cache (both memory and disk)
    pub fn cleanup_old_certificates(&self, max_age_days: u64) -> Result<()> {
        let max_age = std::time::Duration::from_secs(max_age_days * 24 * 60 * 60);
        let now = std::time::SystemTime::now();

        // Clear memory cache
        {
            let mut cache = self
                .memory_cache
                .write()
                .map_err(|_| anyhow!("Failed to acquire memory cache write lock"))?;
            cache.retain(|_, cert| {
                now.duration_since(cert.created_at).unwrap_or_default() < max_age
            });
        }

        // Clear disk cache
        if let Ok(entries) = fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    if let Ok(created) = metadata.created() {
                        if now.duration_since(created).unwrap_or_default() > max_age {
                            if let Err(e) = fs::remove_file(entry.path()) {
                                warn!(
                                    "Failed to remove old certificate file {:?}: {}",
                                    entry.path(),
                                    e
                                );
                            } else {
                                debug!("Removed old certificate file: {:?}", entry.path());
                            }
                        }
                    }
                }
            }
        }

        info!(
            "Certificate cleanup completed, removed certificates older than {} days",
            max_age_days
        );
        Ok(())
    }
}

/// Validate CA certificate and key files
fn validate_ca_files(ca_cert_pem: &str, ca_key_pem: &str) -> Result<bool> {
    // Basic validation - check if they contain PEM markers
    let has_cert_markers = ca_cert_pem.contains("-----BEGIN CERTIFICATE-----")
        && ca_cert_pem.contains("-----END CERTIFICATE-----");

    let has_key_markers = ca_key_pem.contains("-----BEGIN")
        && ca_key_pem.contains("-----END")
        && (ca_key_pem.contains("PRIVATE KEY")
            || ca_key_pem.contains("EC PRIVATE KEY")
            || ca_key_pem.contains("RSA PRIVATE KEY"));

    if !has_cert_markers {
        debug!("CA certificate does not contain valid PEM markers");
        return Ok(false);
    }

    if !has_key_markers {
        debug!("CA private key does not contain valid PEM markers");
        return Ok(false);
    }

    debug!("CA certificate and key files appear to be valid");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_normalize_hostname() {
        let temp_dir = tempdir().unwrap();
        let cache_dir = temp_dir.path().to_str().unwrap();

        // Create dummy CA files for testing
        let ca_cert = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";
        let ca_key = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----";

        let ca_cert_path = temp_dir.path().join("ca.cert.pem");
        let ca_key_path = temp_dir.path().join("ca.key.pem");

        fs::write(&ca_cert_path, ca_cert).unwrap();
        fs::write(&ca_key_path, ca_key).unwrap();

        let manager = DynamicCertificateManager::new(
            cache_dir,
            ca_cert_path.to_str().unwrap(),
            ca_key_path.to_str().unwrap(),
        )
        .unwrap();

        assert_eq!(manager.normalize_hostname("Example.Com"), "example.com");
        assert_eq!(manager.normalize_hostname("example.com:443"), "example.com");
        assert_eq!(
            manager.normalize_hostname("192.168.1.1:8080"),
            "192.168.1.1"
        );
    }

    #[test]
    fn test_cache_key_generation() {
        let temp_dir = tempdir().unwrap();
        let cache_dir = temp_dir.path().to_str().unwrap();

        // Create dummy CA files for testing
        let ca_cert = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";
        let ca_key = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----";

        let ca_cert_path = temp_dir.path().join("ca.cert.pem");
        let ca_key_path = temp_dir.path().join("ca.key.pem");

        fs::write(&ca_cert_path, ca_cert).unwrap();
        fs::write(&ca_key_path, ca_key).unwrap();

        let manager = DynamicCertificateManager::new(
            cache_dir,
            ca_cert_path.to_str().unwrap(),
            ca_key_path.to_str().unwrap(),
        )
        .unwrap();

        // These should generate the same cache key
        assert_eq!(
            manager.normalize_hostname("example.com"),
            manager.normalize_hostname("EXAMPLE.COM")
        );
        assert_eq!(
            manager.normalize_hostname("example.com:443"),
            manager.normalize_hostname("example.com")
        );
    }
}
