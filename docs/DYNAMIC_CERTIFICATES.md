# Dynamic Certificate Generation Implementation

## Overview
This document summarizes the changes made to implement dynamic certificate generation for the HTTPS interception proxy.

## Key Changes Made

### 1. Updated Configuration (`src/proxy/local/config.rs`)
**Removed old options:**
- `cert_file` - No longer needed as certificates are generated dynamically
- `key_file` - No longer needed as certificates are generated dynamically  
- `generate_cert` - Replaced with CA-based system
- `cert_common_name` - Not needed for dynamic generation
- `cert_domains` - Not needed for dynamic generation

**Added new options:**
- `ca_cert_file` (default: "cert.ca.pem") - Path to Root CA certificate
- `ca_key_file` (default: "key.ca.pem") - Path to Root CA private key
- `generate_ca` - Flag to generate new Root CA if needed
- `ca_common_name` (default: "Local Proxy Root CA") - Common name for generated Root CA
- `cert_cache_dir` (default: "cert_cache") - Directory to cache generated certificates

### 2. Certificate Cache System (`src/cert_cache.rs`)
**New module implementing:**
- `DynamicCertificateManager` - Manages certificate generation and caching
- Memory and disk-based certificate caching
- Automatic certificate generation for requested hostnames
- Cache cleanup and statistics functionality
- Hostname normalization (lowercase, port removal)

**Key features:**
- Generates certificates on-demand for any hostname
- Caches certificates both in memory and on disk
- Supports cache cleanup based on age
- Automatically adds "www." variants for domains

### 3. Dynamic TLS Handler (`src/proxy/local/dynamic_tls.rs`)
**New module implementing:**
- `DynamicTlsHandler` - Handles HTTPS CONNECT requests with dynamic certificates
- Parses CONNECT requests to extract target hostnames
- Creates TLS acceptors using dynamically generated certificates
- Caches TLS acceptors for performance
- Handles TLS handshake and connection management

**Key features:**
- Extracts hostname from CONNECT requests
- Generates certificates specific to each hostname
- Caches TLS acceptors to avoid regeneration
- Provides fallback methods for creating PKCS#12 identities

### 4. Updated Main CLI (`src/main.rs`)
**Removed:**
- Entire `GenerateCert` command - No longer needed
- Complex certificate generation CLI options

**Simplified to:**
- `Local` - Local proxy with dynamic certificate generation
- `Remote` - Remote proxy (unchanged)

### 5. Updated Local Proxy Handler (`src/proxy/local/handler.rs`)
**Changes:**
- Modified certificate handling to use Root CA system
- Integrated `DynamicTlsHandler` for CONNECT requests
- Updated to generate/validate Root CA instead of fixed certificates
- Automatic certificate cache directory creation

## How It Works

### 1. Root CA Setup
When starting the local proxy:
- If `--generate-ca` is specified, generates a new Root CA certificate and private key
- Otherwise, validates existing Root CA files
- Creates certificate cache directory if it doesn't exist

### 2. Dynamic Certificate Generation
When a client makes an HTTPS CONNECT request:
1. Extract the target hostname from the CONNECT request
2. Check memory cache for existing certificate
3. Check disk cache for existing certificate  
4. If not found, generate new certificate for the hostname
5. Store in both memory and disk cache
6. Create TLS acceptor and perform handshake
7. Handle the secure connection

### 3. Certificate Caching
- **Memory Cache**: Fast access for frequently accessed sites
- **Disk Cache**: Persistent storage across proxy restarts
- **Cache Keys**: Normalized hostnames (lowercase, no port)
- **Cache Files**: `{hostname}.cert.pem` and `{hostname}.key.pem`

## Usage Examples

### Generate Root CA and Start Proxy
```bash
# Generate new Root CA
rrproxy local --generate-ca --ca-common-name "My Proxy Root CA"

# Use existing Root CA
rrproxy local --ca-cert-file custom_ca.pem --ca-key-file custom_ca_key.pem
```

### Configuration Options
```bash
rrproxy local \
  --listen-addr 127.0.0.1:8080 \
  --ca-cert-file cert.ca.pem \
  --ca-key-file key.ca.pem \
  --cert-cache-dir /path/to/cache \
  --ca-common-name "Custom Root CA"
```

## Benefits of New System

1. **Dynamic Certificate Generation**: No need to pre-generate certificates for specific domains
2. **Improved Security**: Each site gets its own certificate with proper hostname matching
3. **Better Performance**: Certificate caching reduces generation overhead
4. **Simplified Configuration**: No need to specify individual certificate files
5. **Scalability**: Can handle any number of different hostnames automatically
6. **Maintenance**: Automatic cache cleanup prevents disk space issues

## Files Generated

- `cert.ca.pem` - Root CA certificate (install in browser for trust)
- `key.ca.pem` - Root CA private key (keep secure)
- `cert_cache/` - Directory containing cached certificates
  - `{hostname}.cert.pem` - Server certificate for hostname
  - `{hostname}.key.pem` - Private key for hostname

## Browser Configuration

To use the proxy for HTTPS interception:
1. Install `cert.ca.pem` as a trusted Root CA in your browser
2. Configure browser to use proxy at `127.0.0.1:8080`
3. Browse to any HTTPS site - certificates will be generated automatically

## Future Enhancements

1. **Proper CA Signing**: Currently generates self-signed certificates; could be enhanced to use actual CA signing
2. **Certificate Validation**: Add proper certificate chain validation
3. **Performance Optimization**: Implement more sophisticated caching strategies
4. **Configuration**: Add more certificate parameters (validity period, key size, etc.)
5. **Monitoring**: Add metrics and monitoring for certificate generation and cache performance
