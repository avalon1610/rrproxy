pub mod proxy;
pub mod common;
pub mod logging;
pub mod utils;
pub mod cert_gen;
pub mod cert_cache;

use clap::Parser;
use anyhow::Result;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
enum Cli {
    Local(proxy::local::LocalProxyConfig),
    Remote(proxy::remote::RemoteProxyConfig),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli {
        Cli::Local(config) => {
            logging::init_logging(&config.log_level, config.log_file.as_deref())?;
            proxy::local::start(config.clone()).await?;
        }
        Cli::Remote(config) => {
            logging::init_logging(&config.log_level, config.log_file.as_deref())?;
            proxy::remote::start(config.clone()).await?;
        }
    }

    Ok(())
}
