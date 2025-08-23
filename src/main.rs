pub mod proxy;
pub mod common;
pub mod logging;
pub mod utils;
pub mod cert_gen;

use clap::Parser;
use anyhow::Result;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
enum Cli {
    Local(proxy::local::LocalProxyConfig),
    Remote(proxy::remote::RemoteProxyConfig),
    GenerateCert {
        #[clap(long, default_value = "cert.pem")]
        cert_file: String,
        #[clap(long, default_value = "key.pem")]
        key_file: String,
        #[clap(long, default_value = "localhost")]
        common_name: String,
        #[clap(long)]
        domains: Option<Vec<String>>,
    },
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
        Cli::GenerateCert { cert_file, key_file, common_name, domains } => {
            // Initialize minimal logging for certificate generation
            logging::init_logging("info", None)?;
            
            let mut cert_config = cert_gen::CertConfig::default();
            cert_config.common_name = common_name.clone();
            
            if let Some(ref domain_list) = domains {
                cert_config.san_domains = domain_list.clone();
                // Ensure common name is in SAN list
                if !cert_config.san_domains.contains(common_name) {
                    cert_config.san_domains.push(common_name.clone());
                }
            } else {
                // Use common name as the primary SAN
                cert_config.san_domains = vec![common_name.clone()];
            }
            
            println!("Generating certificate for: {}", common_name);
            if let Some(ref domains) = domains {
                println!("Additional domains: {:?}", domains);
            }
            
            cert_gen::generate_and_save_certificate(&cert_config, cert_file, key_file)?;
            println!("Certificate generated successfully!");
            println!("Certificate: {}", cert_file);
            println!("Private key: {}", key_file);
        }
    }

    Ok(())
}
