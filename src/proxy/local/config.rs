use clap::Parser;

#[derive(Parser, Debug, Clone)]
pub struct LocalProxyConfig {
    #[clap(short, long, default_value = "127.0.0.1:8080")]
    pub listen_addr: String,
    #[clap(short, long, default_value = "http://127.0.0.1:8081")]
    pub remote_addr: String,
    #[clap(short, long, default_value_t = 10240)] // 10KB
    pub chunk_size: usize,
    #[clap(short, long)]
    pub firewall_proxy: Option<String>,
    #[clap(long, default_value = "info")]
    pub log_level: String,
    #[clap(long)]
    pub log_file: Option<String>,
    
    // Root CA certificate options for dynamic certificate generation
    #[clap(long, default_value = "cert.ca.pem")]
    pub ca_cert_file: String,
    #[clap(long, default_value = "key.ca.pem")]
    pub ca_key_file: String,
    #[clap(long)]
    pub generate_ca: bool,
    #[clap(long, default_value = "Local Proxy Root CA")]
    pub ca_common_name: String,
    #[clap(long, default_value = "cert_cache")]
    pub cert_cache_dir: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_proxy_config_creation() {
        let config = LocalProxyConfig {
            listen_addr: "127.0.0.1:8080".to_string(),
            remote_addr: "http://127.0.0.1:8081".to_string(),
            chunk_size: 1024,
            firewall_proxy: None,
            log_level: "info".to_string(),
            log_file: None,
            ca_cert_file: "cert.ca.pem".to_string(),
            ca_key_file: "key.ca.pem".to_string(),
            generate_ca: false,
            ca_common_name: "Local Proxy Root CA".to_string(),
            cert_cache_dir: "cert_cache".to_string(),
        };
        
        assert_eq!(config.listen_addr, "127.0.0.1:8080");
        assert_eq!(config.remote_addr, "http://127.0.0.1:8081");
        assert_eq!(config.chunk_size, 1024);
        assert_eq!(config.firewall_proxy, None);
        assert_eq!(config.log_level, "info");
        assert_eq!(config.log_file, None);
        assert_eq!(config.ca_cert_file, "cert.ca.pem");
        assert_eq!(config.ca_key_file, "key.ca.pem");
        assert!(!config.generate_ca);
        assert_eq!(config.ca_common_name, "Local Proxy Root CA");
        assert_eq!(config.cert_cache_dir, "cert_cache");
    }

    #[test]
    fn test_local_proxy_config_with_firewall_proxy() {
        let config = LocalProxyConfig {
            listen_addr: "127.0.0.1:8080".to_string(),
            remote_addr: "http://127.0.0.1:8081".to_string(),
            chunk_size: 1024,
            firewall_proxy: Some("http://proxy.company.com:8080".to_string()),
            log_level: "debug".to_string(),
            log_file: Some("rrproxy.log".to_string()),
            ca_cert_file: "cert.ca.pem".to_string(),
            ca_key_file: "key.ca.pem".to_string(),
            generate_ca: false,
            ca_common_name: "Local Proxy Root CA".to_string(),
            cert_cache_dir: "cert_cache".to_string(),
        };
        
        assert_eq!(config.firewall_proxy, Some("http://proxy.company.com:8080".to_string()));
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.log_file, Some("rrproxy.log".to_string()));
    }

    #[test]
    fn test_local_proxy_config_with_ca_generation() {
        let config = LocalProxyConfig {
            listen_addr: "127.0.0.1:8080".to_string(),
            remote_addr: "http://127.0.0.1:8081".to_string(),
            chunk_size: 1024,
            firewall_proxy: None,
            log_level: "info".to_string(),
            log_file: None,
            ca_cert_file: "custom_ca_cert.pem".to_string(),
            ca_key_file: "custom_ca_key.pem".to_string(),
            generate_ca: true,
            ca_common_name: "Custom Root CA".to_string(),
            cert_cache_dir: "custom_cache".to_string(),
        };
        
        assert_eq!(config.ca_cert_file, "custom_ca_cert.pem");
        assert_eq!(config.ca_key_file, "custom_ca_key.pem");
        assert!(config.generate_ca);
        assert_eq!(config.ca_common_name, "Custom Root CA");
        assert_eq!(config.cert_cache_dir, "custom_cache");
    }
}
