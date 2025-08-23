pub mod local_proxy;
pub mod remote_proxy;
pub mod common;
pub mod logging;

use clap::Parser;
use anyhow::Result;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
enum Cli {
    Local(local_proxy::LocalProxyConfig),
    Remote(remote_proxy::RemoteProxyConfig),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli {
        Cli::Local(config) => {
            logging::init_logging(&config.log_level, config.log_file.as_deref())?;
            local_proxy::start(config.clone()).await?;
        }
        Cli::Remote(config) => {
            logging::init_logging(&config.log_level, config.log_file.as_deref())?;
            remote_proxy::start(config.clone()).await?;
        }
    }

    Ok(())
}
