use anyhow::Result;

pub mod config;
pub mod handler;
pub mod https;
pub mod chunking;
pub mod dynamic_tls;

pub use config::LocalProxyConfig;
pub use handler::start;

pub async fn start_local_proxy(config: LocalProxyConfig) -> Result<()> {
    handler::start(config).await
}
