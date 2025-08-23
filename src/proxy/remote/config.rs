use clap::Parser;

#[derive(Parser, Debug, Clone)]
pub struct RemoteProxyConfig {
    #[clap(short, long, default_value = "127.0.0.1:8081")]
    pub listen_addr: String,
    #[clap(long, default_value = "info")]
    pub log_level: String,
    #[clap(long)]
    pub log_file: Option<String>,
}
