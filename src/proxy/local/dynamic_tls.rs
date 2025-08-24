use super::config::LocalProxyConfig;
use super::chunking::{chunk_and_send_request, forward_single_request};
use crate::cert_cache::{CachedCertificate, DynamicCertificateManager};
use anyhow::{anyhow, Result};
use bytes::Bytes;
use http_body_util::Full;
use native_tls::{Identity, TlsAcceptor};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::TlsAcceptor as TokioTlsAcceptor;
use tracing::{debug, error, info};

/// Dynamic TLS handler that generates certificates on-demand
pub struct DynamicTlsHandler {
    cert_manager: Arc<DynamicCertificateManager>,
    acceptor_cache: Arc<RwLock<HashMap<String, TokioTlsAcceptor>>>,
}

type OriginalRequest = (String, Vec<(String, String)>, Vec<u8>);

impl DynamicTlsHandler {
    /// Create a new dynamic TLS handler
    pub fn new(config: &LocalProxyConfig) -> Result<Self> {
        let cert_manager = Arc::new(DynamicCertificateManager::new(
            &config.cert_cache_dir,
            &config.ca_cert_file,
            &config.ca_key_file,
        )?);

        Ok(Self {
            cert_manager,
            acceptor_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Handle CONNECT request with dynamic certificate generation
    pub async fn handle_connect_request(
        &self,
        mut client_stream: TcpStream,
        request_data: String,
        config: Arc<LocalProxyConfig>,
    ) -> Result<()> {
        // Parse the CONNECT request to extract the target hostname
        let target_host = self.parse_connect_request(&request_data)?;

        info!("HTTPS CONNECT request for: {}", target_host);

        // Get or generate certificate for this hostname
        let cert = self.cert_manager.get_certificate_for_host(&target_host)?;

        // Create TLS acceptor for this certificate
        let acceptor = self.create_tls_acceptor_for_cert(&target_host, &cert)?;

        // Send 200 Connection Established response
        client_stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        // Perform TLS handshake
        match acceptor.accept(client_stream).await {
            Ok(tls_stream) => {
                info!("TLS handshake successful for: {}", target_host);

                // Handle the TLS connection
                self.handle_tls_connection(tls_stream, target_host, config)
                    .await?;
            }
            Err(e) => {
                error!("TLS handshake failed for {}: {}", target_host, e);
                return Err(anyhow!("TLS handshake failed: {}", e));
            }
        }

        Ok(())
    }

    /// Parse CONNECT request to extract target hostname
    fn parse_connect_request(&self, request_data: &str) -> Result<String> {
        let lines: Vec<&str> = request_data.lines().collect();
        if lines.is_empty() {
            return Err(anyhow!("Empty CONNECT request"));
        }

        let first_line = lines[0];
        let parts: Vec<&str> = first_line.split_whitespace().collect();

        if parts.len() < 2 || parts[0] != "CONNECT" {
            return Err(anyhow!("Invalid CONNECT request: {}", first_line));
        }

        let target = parts[1];

        // Extract hostname (remove port if present)
        let hostname = target.split(':').next().unwrap_or(target);

        Ok(hostname.to_string())
    }

    /// Create TLS acceptor for a specific certificate
    fn create_tls_acceptor_for_cert(
        &self,
        hostname: &str,
        cert: &CachedCertificate,
    ) -> Result<TokioTlsAcceptor> {
        // Check if we already have an acceptor cached for this hostname
        {
            let cache = self
                .acceptor_cache
                .read()
                .map_err(|_| anyhow!("Failed to acquire acceptor cache read lock"))?;
            if let Some(acceptor) = cache.get(hostname) {
                debug!("Using cached TLS acceptor for: {}", hostname);
                return Ok(acceptor.clone());
            }
        }

        // Create new acceptor
        let acceptor = self.create_acceptor_from_pem(&cert.cert_pem, &cert.key_pem)?;

        // Cache the acceptor
        {
            let mut cache = self
                .acceptor_cache
                .write()
                .map_err(|_| anyhow!("Failed to acquire acceptor cache write lock"))?;
            cache.insert(hostname.to_string(), acceptor.clone());
        }

        debug!("Created and cached new TLS acceptor for: {}", hostname);
        Ok(acceptor)
    }

    /// Create TLS acceptor from PEM certificate and key
    fn create_acceptor_from_pem(&self, cert_pem: &str, key_pem: &str) -> Result<TokioTlsAcceptor> {
        // Try to create PKCS#12 identity from PEM data
        let identity = self.create_identity_from_pem(cert_pem, key_pem)?;
        let acceptor = TlsAcceptor::new(identity)?;
        Ok(TokioTlsAcceptor::from(acceptor))
    }

    /// Create identity from PEM data
    fn create_identity_from_pem(&self, cert_pem: &str, key_pem: &str) -> Result<Identity> {
        // Try different approaches to create identity

        // Approach 1: Try to use from_pkcs8 with individual PEM data
        let cert_bytes = cert_pem.as_bytes();
        let key_bytes = key_pem.as_bytes();

        if let Ok(identity) = Identity::from_pkcs8(cert_bytes, key_bytes) {
            debug!("Created identity using from_pkcs8 approach");
            return Ok(identity);
        }

        // Approach 2: Create a combined PEM and try again
        let combined_pem = format!("{}\n{}", cert_pem, key_pem);
        let combined_bytes = combined_pem.as_bytes();

        if let Ok(identity) = Identity::from_pkcs8(combined_bytes, combined_bytes) {
            debug!("Created identity using combined PEM approach");
            return Ok(identity);
        }

        // Approach 3: Try to create a PKCS#12 file using OpenSSL if available
        if let Ok(identity) = self.create_pkcs12_with_openssl(cert_pem, key_pem) {
            debug!("Created identity using OpenSSL PKCS#12 approach");
            return Ok(identity);
        }

        // If all approaches fail, return an error
        Err(anyhow!("Failed to create TLS identity from PEM data"))
    }

    /// Try to create PKCS#12 using OpenSSL command
    fn create_pkcs12_with_openssl(&self, cert_pem: &str, key_pem: &str) -> Result<Identity> {
        use std::fs;
        use std::process::Command;
        use tempfile::NamedTempFile;

        // Create temporary files
        let mut cert_file = NamedTempFile::new()?;
        let mut key_file = NamedTempFile::new()?;
        let p12_file = NamedTempFile::new()?;

        // Write PEM data to temporary files
        std::io::Write::write_all(&mut cert_file, cert_pem.as_bytes())?;
        std::io::Write::write_all(&mut key_file, key_pem.as_bytes())?;

        // Run OpenSSL command to create PKCS#12
        let output = Command::new("openssl")
            .args([
                "pkcs12",
                "-export",
                "-in",
                cert_file.path().to_str().unwrap(),
                "-inkey",
                key_file.path().to_str().unwrap(),
                "-out",
                p12_file.path().to_str().unwrap(),
                "-passout",
                "pass:",
                "-nodes",
            ])
            .output();

        match output {
            Ok(result) if result.status.success() => {
                let p12_data = fs::read(p12_file.path())?;
                let identity = Identity::from_pkcs12(&p12_data, "")?;
                Ok(identity)
            }
            _ => Err(anyhow!("OpenSSL command failed or not available")),
        }
    }

    /// Handle the actual TLS connection after handshake
    async fn handle_tls_connection(
        &self,
        mut tls_stream: tokio_native_tls::TlsStream<TcpStream>,
        target_host: String,
        config: Arc<LocalProxyConfig>,
    ) -> Result<()> {
        info!("Handling TLS connection for: {}", target_host);

        // Read the actual HTTP request from the client
        let mut buffer = vec![0u8; 8192];
        let n = tls_stream.read(&mut buffer).await?;

        if n == 0 {
            debug!("Client closed connection immediately");
            return Ok(());
        }

        let request_data = String::from_utf8_lossy(&buffer[..n]);
        debug!(
            "Received HTTP request over TLS: {}",
            request_data.lines().next().unwrap_or("")
        );

        // Parse the HTTP request to reconstruct the full URL
        let full_url = self.reconstruct_full_url(&request_data, &target_host)?;
        debug!("Reconstructed full URL: {}", full_url);

        // Forward the request to the remote proxy
        let response = self
            .forward_to_remote_proxy(&request_data, &full_url, &config)
            .await?;

        // Send the response back to the client via TLS
        tls_stream.write_all(response.as_bytes()).await?;
        tls_stream.flush().await?;

        info!(
            "Forwarded HTTPS request for: {} and sent response back",
            target_host
        );
        Ok(())
    }

    /// Reconstruct full URL from HTTP request and target host
    fn reconstruct_full_url(&self, request_data: &str, target_host: &str) -> Result<String> {
        let lines: Vec<&str> = request_data.lines().collect();
        if lines.is_empty() {
            return Err(anyhow!("Empty HTTP request"));
        }

        let first_line = lines[0];
        let parts: Vec<&str> = first_line.split_whitespace().collect();

        if parts.len() < 2 {
            return Err(anyhow!("Invalid HTTP request line: {}", first_line));
        }

        let _method = parts[0];
        let path = parts[1];

        // Construct full URL
        let full_url = if path.starts_with('/') {
            format!("https://{}{}", target_host, path)
        } else if path.starts_with("http") {
            path.to_string() // Already a full URL
        } else {
            format!("https://{}/{}", target_host, path)
        };

        Ok(full_url)
    }

    /// Forward the request to the remote proxy
    async fn forward_to_remote_proxy(
        &self,
        request_data: &str,
        full_url: &str,
        config: &LocalProxyConfig,
    ) -> Result<String> {
        // Parse the original request
        let (method, headers, body) = self.parse_http_request(request_data)?;

        // Convert to hyper types for using chunking functions
        let method_hyper: hyper::Method = method.parse().map_err(|e| anyhow!("Invalid HTTP method: {}", e))?;
        let uri_hyper: hyper::Uri = full_url.parse().map_err(|e| anyhow!("Invalid URI: {}", e))?;
        let mut request_builder = hyper::Request::builder().method(method_hyper).uri(uri_hyper);
        
        // Convert headers
        for (name, value) in headers {
            request_builder = request_builder.header(name, value);
        }

        let body_bytes = Bytes::from(body);
        let request = request_builder.body(()).map_err(|e| anyhow!("Failed to build request: {}", e))?;
        let (parts, _) = request.into_parts();

        // Check if the request body is large enough to need chunking
        let body_size = body_bytes.len();
        let response = if body_size > config.chunk_size {
            info!(
                "Request body size ({} bytes) exceeds chunk size ({}), will chunk",
                body_size, config.chunk_size
            );
            chunk_and_send_request(parts, body_bytes, Arc::new(config.clone())).await
        } else {
            debug!(
                "Request body size ({} bytes) is within chunk size ({}), sending as single request",
                body_size, config.chunk_size
            );
            forward_single_request(parts, body_bytes, Arc::new(config.clone())).await
        };

        match response {
            Ok(hyper_response) => {
                // Convert hyper response back to string format
                self.convert_hyper_response_to_http(hyper_response).await
            }
            Err(e) => Err(e),
        }
    }

    /// Parse HTTP request into components
    fn parse_http_request(&self, request_data: &str) -> Result<OriginalRequest> {
        let mut lines = request_data.lines();

        // Parse request line
        let first_line = lines.next().ok_or_else(|| anyhow!("Empty HTTP request"))?;
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.is_empty() {
            return Err(anyhow!("Invalid HTTP request line"));
        }
        let method = parts[0].to_string();

        // Parse headers
        let mut headers = Vec::new();
        let mut body_start_index = 0;

        for line in lines {
            if line.is_empty() {
                body_start_index = request_data
                    .find("\r\n\r\n")
                    .or_else(|| request_data.find("\n\n"))
                    .map(|pos| {
                        pos + if request_data.contains("\r\n\r\n") {
                            4
                        } else {
                            2
                        }
                    })
                    .unwrap_or(request_data.len());
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim().to_string();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.push((name, value));
            }
        }

        // Extract body
        let body = if body_start_index < request_data.len() {
            request_data.as_bytes()[body_start_index..].to_vec()
        } else {
            Vec::new()
        };

        Ok((method, headers, body))
    }

    /// Convert hyper Response to HTTP response string
    async fn convert_hyper_response_to_http(&self, response: hyper::Response<Full<Bytes>>) -> Result<String> {
        let (parts, body) = response.into_parts();
        let status = parts.status;
        let headers = parts.headers;
        
        // Get body bytes
        let body_bytes = http_body_util::BodyExt::collect(body).await
            .map_err(|e| anyhow!("Failed to read response body: {}", e))?
            .to_bytes();

        // Build HTTP response
        let mut http_response = format!(
            "HTTP/1.1 {} {}\r\n",
            status.as_u16(),
            status.canonical_reason().unwrap_or("")
        );

        // Add headers
        for (name, value) in headers.iter() {
            if let Ok(value_str) = value.to_str() {
                http_response.push_str(&format!("{}: {}\r\n", name, value_str));
            }
        }

        // Add content length
        http_response.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
        http_response.push_str("\r\n");

        // Add body
        http_response.push_str(&String::from_utf8_lossy(&body_bytes));

        Ok(http_response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect_request() {
        let handler = create_test_handler();

        // Test basic CONNECT request
        let request = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let hostname = handler.parse_connect_request(request).unwrap();
        assert_eq!(hostname, "example.com");

        // Test CONNECT without port
        let request = "CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let hostname = handler.parse_connect_request(request).unwrap();
        assert_eq!(hostname, "example.com");

        // Test with IP address
        let request = "CONNECT 192.168.1.1:443 HTTP/1.1\r\n\r\n";
        let hostname = handler.parse_connect_request(request).unwrap();
        assert_eq!(hostname, "192.168.1.1");
    }

    #[test]
    fn test_invalid_connect_requests() {
        let handler = create_test_handler();

        // Test empty request
        assert!(handler.parse_connect_request("").is_err());

        // Test non-CONNECT request
        let request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(handler.parse_connect_request(request).is_err());

        // Test malformed CONNECT
        let request = "CONNECT\r\n\r\n";
        assert!(handler.parse_connect_request(request).is_err());
    }

    fn create_test_handler() -> DynamicTlsHandler {
        use std::fs;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let cache_dir = temp_dir.path().join("cache");
        fs::create_dir_all(&cache_dir).unwrap();

        // Create dummy CA files
        let ca_cert = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";
        let ca_key = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----";

        let ca_cert_path = temp_dir.path().join("ca.cert.pem");
        let ca_key_path = temp_dir.path().join("ca.key.pem");

        fs::write(&ca_cert_path, ca_cert).unwrap();
        fs::write(&ca_key_path, ca_key).unwrap();

        let config = LocalProxyConfig {
            listen_addr: "127.0.0.1:8080".to_string(),
            remote_addr: "http://127.0.0.1:8081".to_string(),
            chunk_size: 1024,
            firewall_proxy: None,
            log_level: "info".to_string(),
            log_file: None,
            ca_cert_file: ca_cert_path.to_str().unwrap().to_string(),
            ca_key_file: ca_key_path.to_str().unwrap().to_string(),
            generate_ca: false,
            ca_common_name: "Test CA".to_string(),
            cert_cache_dir: cache_dir.to_str().unwrap().to_string(),
        };

        DynamicTlsHandler::new(&config).unwrap()
    }
}
