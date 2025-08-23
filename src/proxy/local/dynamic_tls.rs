use anyhow::{anyhow, Result};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, error};
use native_tls::{Identity, TlsAcceptor};
use tokio_native_tls::TlsAcceptor as TokioTlsAcceptor;
use std::collections::HashMap;
use std::sync::RwLock;
use super::config::LocalProxyConfig;
use crate::cert_cache::{DynamicCertificateManager, CachedCertificate};

/// Dynamic TLS handler that generates certificates on-demand
pub struct DynamicTlsHandler {
    cert_manager: Arc<DynamicCertificateManager>,
    acceptor_cache: Arc<RwLock<HashMap<String, TokioTlsAcceptor>>>,
}

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
        config: Arc<LocalProxyConfig>
    ) -> Result<()> {
        // Parse the CONNECT request to extract the target hostname
        let target_host = self.parse_connect_request(&request_data)?;
        
        info!("HTTPS CONNECT request for: {}", target_host);
        
        // Get or generate certificate for this hostname
        let cert = self.cert_manager.get_certificate_for_host(&target_host)?;
        
        // Create TLS acceptor for this certificate
        let acceptor = self.create_tls_acceptor_for_cert(&target_host, &cert)?;
        
        // Send 200 Connection Established response
        client_stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        
        // Perform TLS handshake
        match acceptor.accept(client_stream).await {
            Ok(tls_stream) => {
                info!("TLS handshake successful for: {}", target_host);
                
                // Handle the TLS connection
                self.handle_tls_connection(tls_stream, target_host, config).await?;
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
    fn create_tls_acceptor_for_cert(&self, hostname: &str, cert: &CachedCertificate) -> Result<TokioTlsAcceptor> {
        // Check if we already have an acceptor cached for this hostname
        {
            let cache = self.acceptor_cache.read()
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
            let mut cache = self.acceptor_cache.write()
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
        use std::process::Command;
        use std::fs;
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
            .args(&[
                "pkcs12", "-export",
                "-in", cert_file.path().to_str().unwrap(),
                "-inkey", key_file.path().to_str().unwrap(),
                "-out", p12_file.path().to_str().unwrap(),
                "-passout", "pass:",
                "-nodes"
            ])
            .output();

        match output {
            Ok(result) if result.status.success() => {
                let p12_data = fs::read(p12_file.path())?;
                let identity = Identity::from_pkcs12(&p12_data, "")?;
                Ok(identity)
            }
            _ => Err(anyhow!("OpenSSL command failed or not available"))
        }
    }

    /// Handle the actual TLS connection after handshake
    async fn handle_tls_connection(
        &self,
        mut tls_stream: tokio_native_tls::TlsStream<TcpStream>,
        target_host: String,
        config: Arc<LocalProxyConfig>
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
        debug!("Received HTTP request over TLS: {}", request_data.lines().next().unwrap_or(""));

        // Parse the HTTP request to reconstruct the full URL
        let full_url = self.reconstruct_full_url(&request_data, &target_host)?;
        debug!("Reconstructed full URL: {}", full_url);

        // Forward the request to the remote proxy
        let response = self.forward_to_remote_proxy(&request_data, &full_url, &config).await?;

        // Send the response back to the client via TLS
        tls_stream.write_all(response.as_bytes()).await?;
        tls_stream.flush().await?;

        info!("Forwarded HTTPS request for: {} and sent response back", target_host);
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
        config: &LocalProxyConfig
    ) -> Result<String> {
        // Parse the original request
        let (method, headers, body) = self.parse_http_request(request_data)?;
        
        // Create a new HTTP request to send to the remote proxy
        let client = if let Some(ref firewall_proxy) = config.firewall_proxy {
            // Use firewall proxy if configured
            let proxy = reqwest::Proxy::all(firewall_proxy)
                .map_err(|e| anyhow!("Failed to create firewall proxy: {}", e))?;
            reqwest::Client::builder()
                .proxy(proxy)
                .build()
                .map_err(|e| anyhow!("Failed to create HTTP client with proxy: {}", e))?
        } else {
            reqwest::Client::new()
        };

        // Check if the request body is large enough to need chunking
        let body_size = body.len();
        if body_size > config.chunk_size {
            info!("Request body size ({} bytes) exceeds chunk size ({}), will chunk", body_size, config.chunk_size);
            self.forward_chunked_request(&client, &method, full_url, &headers, &body, config).await
        } else {
            debug!("Request body size ({} bytes) is within chunk size ({}), sending as single request", body_size, config.chunk_size);
            self.forward_single_request(&client, &method, full_url, &headers, &body, config).await
        }
    }

    /// Parse HTTP request into components
    fn parse_http_request(&self, request_data: &str) -> Result<(String, Vec<(String, String)>, Vec<u8>)> {
        let mut lines = request_data.lines();
        
        // Parse request line
        let first_line = lines.next().ok_or_else(|| anyhow!("Empty HTTP request"))?;
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 1 {
            return Err(anyhow!("Invalid HTTP request line"));
        }
        let method = parts[0].to_string();

        // Parse headers
        let mut headers = Vec::new();
        let mut body_start_index = 0;
        
        for (_i, line) in lines.enumerate() {
            if line.is_empty() {
                body_start_index = request_data.find("\r\n\r\n")
                    .or_else(|| request_data.find("\n\n"))
                    .map(|pos| pos + if request_data.contains("\r\n\r\n") { 4 } else { 2 })
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
            request_data[body_start_index..].as_bytes().to_vec()
        } else {
            Vec::new()
        };

        Ok((method, headers, body))
    }

    /// Forward request as a single request (no chunking)
    async fn forward_single_request(
        &self,
        client: &reqwest::Client,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        config: &LocalProxyConfig
    ) -> Result<String> {
        debug!("Forwarding single request to remote proxy: {}", config.remote_addr);

        let mut request = match method {
            "GET" => client.get(&config.remote_addr),
            "POST" => client.post(&config.remote_addr),
            "PUT" => client.put(&config.remote_addr),
            "DELETE" => client.delete(&config.remote_addr),
            "PATCH" => client.patch(&config.remote_addr),
            _ => client.post(&config.remote_addr), // Default to POST for other methods
        };

        // Add original URL as a header
        request = request.header("X-Original-Url", url);
        
        // Add original headers (excluding problematic ones)
        for (name, value) in headers {
            let name_lower = name.to_lowercase();
            if !name_lower.starts_with("host") && !name_lower.starts_with("content-length") {
                request = request.header(name, value);
            }
        }

        // Add body if present
        if !body.is_empty() {
            request = request.body(body.to_vec());
        }

        // Send the request
        let response = request.send().await
            .map_err(|e| anyhow!("Failed to forward request to remote proxy: {}", e))?;

        // Convert response back to HTTP format
        self.convert_response_to_http(response).await
    }

    /// Forward request as chunked requests
    async fn forward_chunked_request(
        &self,
        client: &reqwest::Client,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        config: &LocalProxyConfig
    ) -> Result<String> {
        use uuid::Uuid;

        let transaction_id = Uuid::new_v4().to_string();
        let chunks: Vec<&[u8]> = body.chunks(config.chunk_size).collect();
        let total_chunks = chunks.len();

        info!("Chunking request into {} chunks for transaction {}", total_chunks, transaction_id);

        // Send all chunks
        for (chunk_index, chunk) in chunks.iter().enumerate() {
            let is_last_chunk = chunk_index == total_chunks - 1;
            
            let mut request = client.post(&config.remote_addr);
            
            // Add chunking headers
            request = request
                .header("X-Transaction-Id", &transaction_id)
                .header("X-Chunk-Index", chunk_index.to_string())
                .header("X-Total-Chunks", total_chunks.to_string())
                .header("X-Is-Last-Chunk", is_last_chunk.to_string())
                .header("X-Original-Url", url)
                .header("X-Original-Method", method);

            // Add original headers (excluding problematic ones)
            for (name, value) in headers {
                let name_lower = name.to_lowercase();
                if !name_lower.starts_with("host") && !name_lower.starts_with("content-length") {
                    request = request.header(name, value);
                }
            }

            // Add chunk body
            request = request.body(chunk.to_vec());

            // Send chunk
            let response = request.send().await
                .map_err(|e| anyhow!("Failed to send chunk {} to remote proxy: {}", chunk_index, e))?;

            if is_last_chunk {
                // Return the response from the last chunk
                return self.convert_response_to_http(response).await;
            } else {
                // For non-last chunks, just ensure they were accepted
                if !response.status().is_success() {
                    return Err(anyhow!("Remote proxy rejected chunk {}: {}", chunk_index, response.status()));
                }
            }
        }

        Err(anyhow!("Chunked request completed but no final response received"))
    }

    /// Convert reqwest Response to HTTP response string
    async fn convert_response_to_http(&self, response: reqwest::Response) -> Result<String> {
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.bytes().await
            .map_err(|e| anyhow!("Failed to read response body: {}", e))?;

        // Build HTTP response
        let mut http_response = format!("HTTP/1.1 {} {}\r\n", status.as_u16(), status.canonical_reason().unwrap_or(""));

        // Add headers
        for (name, value) in headers.iter() {
            if let Ok(value_str) = value.to_str() {
                http_response.push_str(&format!("{}: {}\r\n", name, value_str));
            }
        }

        // Add content length
        http_response.push_str(&format!("Content-Length: {}\r\n", body.len()));
        http_response.push_str("\r\n");

        // Add body
        http_response.push_str(&String::from_utf8_lossy(&body));

        Ok(http_response)
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> Result<String> {
        let cert_stats = self.cert_manager.get_cache_stats()?;
        let acceptor_count = self.acceptor_cache.read()
            .map_err(|_| anyhow!("Failed to acquire acceptor cache read lock"))?
            .len();

        Ok(format!(
            "Certificate Cache Stats:\n\
             - Memory cache: {} certificates\n\
             - Disk cache: {} certificates\n\
             - Cache directory: {}\n\
             - TLS acceptors cached: {}",
            cert_stats.memory_cache_size,
            cert_stats.disk_cache_size,
            cert_stats.cache_directory,
            acceptor_count
        ))
    }

    /// Clean up old certificates and acceptors
    pub fn cleanup_cache(&self, max_age_days: u64) -> Result<()> {
        // Clean up certificate cache
        self.cert_manager.cleanup_old_certificates(max_age_days)?;
        
        // Clear acceptor cache (they will be recreated as needed)
        {
            let mut cache = self.acceptor_cache.write()
                .map_err(|_| anyhow!("Failed to acquire acceptor cache write lock"))?;
            cache.clear();
        }

        info!("TLS handler cache cleanup completed");
        Ok(())
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
        use tempfile::tempdir;
        use std::fs;

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
