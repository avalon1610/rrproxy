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
    
    // Certificate options
    #[clap(long, default_value = "cert.pem")]
    pub cert_file: String,
    #[clap(long, default_value = "key.pem")]
    pub key_file: String,
    #[clap(long)]
    pub generate_cert: bool,
    #[clap(long)]
    pub cert_common_name: Option<String>,
    #[clap(long)]
    pub cert_domains: Option<Vec<String>>,
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
            cert_file: "cert.pem".to_string(),
            key_file: "key.pem".to_string(),
            generate_cert: false,
            cert_common_name: None,
            cert_domains: None,
        };
        
        assert_eq!(config.listen_addr, "127.0.0.1:8080");
        assert_eq!(config.remote_addr, "http://127.0.0.1:8081");
        assert_eq!(config.chunk_size, 1024);
        assert_eq!(config.firewall_proxy, None);
        assert_eq!(config.log_level, "info");
        assert_eq!(config.log_file, None);
        assert_eq!(config.cert_file, "cert.pem");
        assert_eq!(config.key_file, "key.pem");
        assert!(!config.generate_cert);
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
            cert_file: "cert.pem".to_string(),
            key_file: "key.pem".to_string(),
            generate_cert: false,
            cert_common_name: None,
            cert_domains: None,
        };
        
        assert_eq!(config.firewall_proxy, Some("http://proxy.company.com:8080".to_string()));
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.log_file, Some("rrproxy.log".to_string()));
    }

    #[test]
    fn test_local_proxy_config_with_cert_generation() {
        let config = LocalProxyConfig {
            listen_addr: "127.0.0.1:8080".to_string(),
            remote_addr: "http://127.0.0.1:8081".to_string(),
            chunk_size: 1024,
            firewall_proxy: None,
            log_level: "info".to_string(),
            log_file: None,
            cert_file: "custom_cert.pem".to_string(),
            key_file: "custom_key.pem".to_string(),
            generate_cert: true,
            cert_common_name: Some("example.com".to_string()),
            cert_domains: Some(vec!["example.com".to_string(), "www.example.com".to_string()]),
        };
        
        assert_eq!(config.cert_file, "custom_cert.pem");
        assert_eq!(config.key_file, "custom_key.pem");
        assert!(config.generate_cert);
        assert_eq!(config.cert_common_name, Some("example.com".to_string()));
        assert_eq!(config.cert_domains, Some(vec!["example.com".to_string(), "www.example.com".to_string()]));
    }
}
