pub mod config;
pub mod handler;
pub mod chunking;
pub mod tunnel;

pub use config::RemoteProxyConfig;
pub use handler::start;

pub async fn start_remote_proxy(config: RemoteProxyConfig) -> anyhow::Result<()> {
    handler::start(config).await
}
