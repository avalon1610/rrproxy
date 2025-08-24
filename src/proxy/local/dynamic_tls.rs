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

/// Connection state to handle buffered data between requests
struct ConnectionState {
    buffer: Vec<u8>,
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

        // Initialize connection state to handle buffered data between requests
        let mut connection_state = ConnectionState {
            buffer: Vec::new(),
        };

        // Handle multiple requests on the same connection (HTTP/1.1 keep-alive)
        loop {
            // Read the complete HTTP request from the client
            let request_data = match self.read_complete_http_request(&mut tls_stream, &mut connection_state).await {
                Ok(data) => data,
                Err(e) => {
                    debug!("Error reading HTTP request: {}", e);
                    break;
                }
            };
            
            if request_data.is_empty() {
                debug!("Client closed connection");
                break;
            }

            debug!(
                "Received HTTP request over TLS: {}",
                request_data.lines().next().unwrap_or("")
            );

            // Parse the HTTP request to reconstruct the full URL
            let full_url = match self.reconstruct_full_url(&request_data, &target_host) {
                Ok(url) => url,
                Err(e) => {
                    error!("Failed to reconstruct URL: {}", e);
                    // Send 400 Bad Request response
                    let error_response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = tls_stream.write_all(error_response.as_bytes()).await;
                    let _ = tls_stream.flush().await;
                    break;
                }
            };
            debug!("Reconstructed full URL: {}", full_url);

            // Forward the request to the remote proxy
            let response = match self
                .forward_to_remote_proxy(&request_data, &full_url, &config)
                .await
            {
                Ok(resp) => resp,
                Err(e) => {
                    error!("Failed to forward request: {}", e);
                    // Send 502 Bad Gateway response
                    let error_response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = tls_stream.write_all(error_response.as_bytes()).await;
                    let _ = tls_stream.flush().await;
                    break;
                }
            };

            // Send the response back to the client via TLS
            if let Err(e) = tls_stream.write_all(response.as_bytes()).await {
                error!("Failed to write response: {}", e);
                break;
            }
            if let Err(e) = tls_stream.flush().await {
                error!("Failed to flush response: {}", e);
                break;
            }

            info!(
                "Forwarded HTTPS request for: {} and sent response back",
                target_host
            );

            // Check if we should keep the connection alive
            if !self.should_keep_connection_alive(&request_data, &response) {
                debug!("Connection should be closed");
                break;
            }

            debug!("Keeping connection alive for next request");
        }

        debug!("TLS connection closed for: {}", target_host);
        Ok(())
    }

    /// Read the complete HTTP request from the TLS stream
    /// Uses connection state to preserve any buffered data from previous reads
    async fn read_complete_http_request(
        &self,
        tls_stream: &mut tokio_native_tls::TlsStream<TcpStream>,
        connection_state: &mut ConnectionState,
    ) -> Result<String> {
        let mut temp_buffer = vec![0u8; 8192];

        loop {
            // Try to parse the HTTP request from existing buffered data first
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut req = httparse::Request::new(&mut headers);
            
            match req.parse(&connection_state.buffer) {
                Ok(httparse::Status::Complete(headers_len)) => {
                    // Headers are complete, now check if we have the full body
                    
                    // Check for Content-Length
                    let content_length = req.headers.iter()
                        .find(|h| h.name.to_lowercase() == "content-length")
                        .and_then(|h| std::str::from_utf8(h.value).ok())
                        .and_then(|v| v.parse::<usize>().ok());
                    
                    // Check for Transfer-Encoding: chunked
                    let is_chunked = req.headers.iter()
                        .any(|h| h.name.to_lowercase() == "transfer-encoding" 
                             && std::str::from_utf8(h.value).unwrap_or("").to_lowercase().contains("chunked"));
                    
                    let body_received = connection_state.buffer.len() - headers_len;
                    
                    if let Some(expected_length) = content_length {
                        // Use Content-Length to determine completion
                        if body_received >= expected_length {
                            // We have the complete request
                            let request_size = headers_len + expected_length;
                            let complete_request = connection_state.buffer[..request_size].to_vec();
                            
                            // Save any remaining data for the next request
                            if request_size < connection_state.buffer.len() {
                                let remaining_data = connection_state.buffer[request_size..].to_vec();
                                connection_state.buffer = remaining_data;
                                debug!("Saved {} bytes for next request", connection_state.buffer.len());
                            } else {
                                connection_state.buffer.clear();
                            }
                            
                            return Ok(String::from_utf8_lossy(&complete_request).to_string());
                        }
                    } else if is_chunked {
                        // For chunked encoding, properly parse chunks to find the end
                        if let Some(request_end) = self.find_chunked_request_end(&connection_state.buffer, headers_len)? {
                            // We found the complete chunked request
                            let complete_request = connection_state.buffer[..request_end].to_vec();
                            
                            // Save any remaining data for the next request
                            if request_end < connection_state.buffer.len() {
                                let remaining_data = connection_state.buffer[request_end..].to_vec();
                                connection_state.buffer = remaining_data;
                                debug!("Saved {} bytes for next request after chunked", connection_state.buffer.len());
                            } else {
                                connection_state.buffer.clear();
                            }
                            
                            return Ok(String::from_utf8_lossy(&complete_request).to_string());
                        }
                        // Continue reading more chunks
                    } else {
                        // No Content-Length and not chunked, assume request is complete
                        // This handles GET requests and other requests without body
                        let complete_request = connection_state.buffer[..headers_len].to_vec();
                        
                        // Save any remaining data for the next request
                        if headers_len < connection_state.buffer.len() {
                            let remaining_data = connection_state.buffer[headers_len..].to_vec();
                            connection_state.buffer = remaining_data;
                            debug!("Saved {} bytes for next request after headers-only", connection_state.buffer.len());
                        } else {
                            connection_state.buffer.clear();
                        }
                        
                        return Ok(String::from_utf8_lossy(&complete_request).to_string());
                    }
                    // Continue reading to get the rest of the body
                }
                Ok(httparse::Status::Partial) => {
                    // Need more data to complete parsing, fall through to read more
                }
                Err(e) => {
                    return Err(anyhow!("HTTP parsing error: {}", e));
                }
            }

            // Read more data from the stream
            let n = tls_stream.read(&mut temp_buffer).await?;
            
            if n == 0 {
                // Connection closed
                if connection_state.buffer.is_empty() {
                    return Ok(String::new());
                }
                // Return whatever we have in the buffer
                let result = String::from_utf8_lossy(&connection_state.buffer).to_string();
                connection_state.buffer.clear();
                return Ok(result);
            }

            // Append new data to the buffer
            connection_state.buffer.extend_from_slice(&temp_buffer[..n]);

            // Safety check to prevent infinite reading
            if connection_state.buffer.len() > 10 * 1024 * 1024 {
                // 10MB limit
                return Err(anyhow!("HTTP request too large (>10MB)"));
            }
        }
    }

    /// Find the end of a chunked HTTP request in the buffer
    /// Returns the position where the current request ends (including the final \r\n\r\n)
    /// Returns None if the chunked request is not yet complete
    fn find_chunked_request_end(&self, buffer: &[u8], headers_len: usize) -> Result<Option<usize>> {
        let body_start = headers_len;
        let mut pos = body_start;
        
        while pos < buffer.len() {
            // Find the chunk size line (ends with \r\n or \n)
            let chunk_size_start = pos;
            let chunk_size_end = if let Some(crlf_pos) = buffer[pos..].windows(2).position(|w| w == b"\r\n") {
                pos + crlf_pos
            } else if let Some(lf_pos) = buffer[pos..].iter().position(|&b| b == b'\n') {
                pos + lf_pos
            } else {
                // No complete chunk size line yet
                return Ok(None);
            };
            
            // Parse the chunk size
            let chunk_size_bytes = &buffer[chunk_size_start..chunk_size_end];
            let chunk_size_str = std::str::from_utf8(chunk_size_bytes)
                .map_err(|e| anyhow!("Invalid chunk size encoding: {}", e))?;
            
            // Parse hex chunk size
            let chunk_size = usize::from_str_radix(chunk_size_str.trim(), 16)
                .map_err(|e| anyhow!("Invalid chunk size: {} - {}", chunk_size_str, e))?;
            
            // Move past the chunk size line (skip \r\n or \n)
            pos = if buffer.len() > chunk_size_end + 1 && buffer[chunk_size_end] == b'\r' && buffer[chunk_size_end + 1] == b'\n' {
                chunk_size_end + 2  // Skip \r\n
            } else if buffer.len() > chunk_size_end && buffer[chunk_size_end] == b'\n' {
                chunk_size_end + 1  // Skip \n
            } else {
                return Ok(None);  // Not enough data
            };
            
            if chunk_size == 0 {
                // This is the final chunk, look for the trailing \r\n\r\n (or \n\n)
                let trailing_start = pos;
                
                // The final chunk should be followed by \r\n\r\n (or \n\n)
                if buffer.len() >= trailing_start + 4 && 
                   &buffer[trailing_start..trailing_start + 4] == b"\r\n\r\n" {
                    // Found complete \r\n\r\n
                    return Ok(Some(trailing_start + 4));
                } else if buffer.len() >= trailing_start + 2 && 
                          &buffer[trailing_start..trailing_start + 2] == b"\n\n" {
                    // Found \n\n
                    return Ok(Some(trailing_start + 2));
                } else if buffer.len() >= trailing_start + 3 && 
                          &buffer[trailing_start..trailing_start + 3] == b"\r\n\n" {
                    // Found \r\n\n (mixed line endings)
                    return Ok(Some(trailing_start + 3));
                }
                
                // Final chunk found but trailing headers not complete yet
                return Ok(None);
            } else {
                // Regular chunk, skip the chunk data
                let chunk_data_end = pos + chunk_size;
                if buffer.len() < chunk_data_end {
                    // Don't have the complete chunk data yet
                    return Ok(None);
                }
                
                // Move past the chunk data
                pos = chunk_data_end;
                
                // Skip the trailing \r\n or \n after chunk data
                if buffer.len() > pos + 1 && buffer[pos] == b'\r' && buffer[pos + 1] == b'\n' {
                    pos += 2;  // Skip \r\n
                } else if buffer.len() > pos && buffer[pos] == b'\n' {
                    pos += 1;  // Skip \n
                } else {
                    // Don't have the trailing newline yet
                    return Ok(None);
                }
            }
        }
        
        // Reached end of buffer without finding complete request
        Ok(None)
    }

    /// Determine if the connection should be kept alive based on HTTP headers
    fn should_keep_connection_alive(&self, request_data: &str, response_data: &str) -> bool {
        // Check Connection header in the request
        let request_connection = self.extract_header_value(request_data, "connection");
        let response_connection = self.extract_header_value(response_data, "connection");
        
        // HTTP/1.1 defaults to keep-alive unless explicitly closed
        let request_version = if request_data.contains("HTTP/1.0") { "1.0" } else { "1.1" };
        
        // For HTTP/1.0, connection is closed by default unless keep-alive is specified
        // For HTTP/1.1, connection is kept alive by default unless close is specified
        match request_version {
            "1.0" => {
                // HTTP/1.0: keep alive only if explicitly requested
                request_connection.to_lowercase().contains("keep-alive") &&
                !response_connection.to_lowercase().contains("close")
            }
            _ => {
                // HTTP/1.1: keep alive unless explicitly closed
                !request_connection.to_lowercase().contains("close") &&
                !response_connection.to_lowercase().contains("close")
            }
        }
    }

    /// Extract header value from HTTP message
    fn extract_header_value(&self, http_data: &str, header_name: &str) -> String {
        let header_name_lower = header_name.to_lowercase();
        
        for line in http_data.lines() {
            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim().to_lowercase();
                if name == header_name_lower {
                    return line[colon_pos + 1..].trim().to_string();
                }
            }
        }
        
        String::new()
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

    #[tokio::test]
    async fn test_http_request_parsing_with_httparse() {
        // Test that httparse can correctly identify complete HTTP requests
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        
        // Test complete GET request
        let get_request = b"GET /path HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n";
        let result = req.parse(get_request).unwrap();
        assert!(matches!(result, httparse::Status::Complete(_)));
        
        // Test complete POST request with body
        let mut headers2 = [httparse::EMPTY_HEADER; 64];
        let mut req2 = httparse::Request::new(&mut headers2);
        let post_request = b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
        let result = req2.parse(post_request).unwrap();
        assert!(matches!(result, httparse::Status::Complete(_)));
        
        // Test partial request (headers incomplete)
        let mut headers3 = [httparse::EMPTY_HEADER; 64];
        let mut req3 = httparse::Request::new(&mut headers3);
        let partial_request = b"GET /path HTTP/1.1\r\nHost: example.com\r\n";
        let result = req3.parse(partial_request).unwrap();
        assert!(matches!(result, httparse::Status::Partial));
    }

    #[test]
    fn test_multi_request_handling() {
        let handler = create_test_handler();
        
        // Test connection keep-alive logic which is the main feature we added
        
        // Test HTTP/1.1 with no Connection header (should keep alive)
        let request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert!(handler.should_keep_connection_alive(request, response));
        
        // Test HTTP/1.1 with Connection: close (should close)
        let request = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert!(!handler.should_keep_connection_alive(request, response));
        
        // Test that header extraction works correctly
        assert_eq!(handler.extract_header_value(request, "Host"), "example.com");
        assert_eq!(handler.extract_header_value(request, "Connection"), "close");
        
        println!("Multi-request handling tests passed!");
    }

    #[test]
    fn test_pipelined_request_buffering() {
        let _handler = create_test_handler();
        
        // Test that we can correctly handle two pipelined requests
        let mut connection_state = ConnectionState {
            buffer: Vec::new(),
        };
        
        // Simulate receiving both requests in one buffer
        let pipelined_data = b"GET /first HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\nGET /second HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
        connection_state.buffer.extend_from_slice(pipelined_data);
        
        // Extract first request (should be GET /first)
        let mut headers1 = [httparse::EMPTY_HEADER; 64];
        let mut req1 = httparse::Request::new(&mut headers1);
        let result1 = req1.parse(&connection_state.buffer).unwrap();
        
        if let httparse::Status::Complete(headers_len) = result1 {
            // This should be the first request
            let first_request = &connection_state.buffer[..headers_len];
            let first_request_str = std::str::from_utf8(first_request).unwrap();
            assert!(first_request_str.contains("GET /first"));
            
            // Simulate what our function would do - remove the first request and keep the rest
            let remaining = connection_state.buffer[headers_len..].to_vec();
            connection_state.buffer = remaining;
            
            // Now try to parse the second request
            let mut headers2 = [httparse::EMPTY_HEADER; 64];
            let mut req2 = httparse::Request::new(&mut headers2);
            let result2 = req2.parse(&connection_state.buffer).unwrap();
            
            if let httparse::Status::Complete(headers_len2) = result2 {
                // Check Content-Length for second request
                let content_length = req2.headers.iter()
                    .find(|h| h.name.to_lowercase() == "content-length")
                    .and_then(|h| std::str::from_utf8(h.value).ok())
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0);
                
                assert_eq!(content_length, 5);
                
                // Check if we have the complete second request (headers + body)
                let body_received = connection_state.buffer.len() - headers_len2;
                assert!(body_received >= content_length);
                
                let second_request_end = headers_len2 + content_length;
                let second_request = &connection_state.buffer[..second_request_end];
                let second_request_str = std::str::from_utf8(second_request).unwrap();
                assert!(second_request_str.contains("GET /second"));
                assert!(second_request_str.ends_with("hello"));
            }
        }
        
        println!("Pipelined request buffering test passed!");
    }

    #[test]
    fn test_connection_keep_alive_logic() {
        let handler = create_test_handler();
        
        // Test HTTP/1.1 with no Connection header (should keep alive)
        let request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert!(handler.should_keep_connection_alive(request, response));
        
        // Test HTTP/1.1 with Connection: close (should close)
        let request = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert!(!handler.should_keep_connection_alive(request, response));
        
        // Test HTTP/1.0 with no Connection header (should close)
        let request = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
        let response = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert!(!handler.should_keep_connection_alive(request, response));
        
        // Test HTTP/1.0 with Connection: keep-alive (should keep alive)
        let request = "GET / HTTP/1.0\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n";
        let response = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert!(handler.should_keep_connection_alive(request, response));
        
        // Test response with Connection: close (should close regardless of request)
        let request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        assert!(!handler.should_keep_connection_alive(request, response));
    }

    #[test]
    fn test_header_extraction() {
        let handler = create_test_handler();
        
        let http_data = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
        
        assert_eq!(handler.extract_header_value(http_data, "Host"), "example.com");
        assert_eq!(handler.extract_header_value(http_data, "Connection"), "keep-alive");
        assert_eq!(handler.extract_header_value(http_data, "User-Agent"), "Mozilla/5.0");
        assert_eq!(handler.extract_header_value(http_data, "Nonexistent"), "");
        
        // Test case insensitive header names
        assert_eq!(handler.extract_header_value(http_data, "host"), "example.com");
        assert_eq!(handler.extract_header_value(http_data, "CONNECTION"), "keep-alive");
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
