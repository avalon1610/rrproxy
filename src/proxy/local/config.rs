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
        };
        
        assert_eq!(config.listen_addr, "127.0.0.1:8080");
        assert_eq!(config.remote_addr, "http://127.0.0.1:8081");
        assert_eq!(config.chunk_size, 1024);
        assert_eq!(config.firewall_proxy, None);
        assert_eq!(config.log_level, "info");
        assert_eq!(config.log_file, None);
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
        };
        
        assert_eq!(config.firewall_proxy, Some("http://proxy.company.com:8080".to_string()));
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.log_file, Some("rrproxy.log".to_string()));
    }
}
