# Certificate Generation Features

The rrproxy project now supports three different certificate generation modes to address various deployment scenarios and security requirements.

## Certificate Generation Modes

### 1. Self-Signed Certificates (Default)
The simplest mode that generates self-signed certificates suitable for development and testing.

```bash
# Generate self-signed certificate (default behavior)
cargo run -- generate-cert --common-name localhost
cargo run -- generate-cert --self-signed --common-name example.com
```

**Use cases:**
- Development environments
- Internal testing
- Quick prototyping
- When certificate authority infrastructure is not available

**Limitations:**
- Browsers will show security warnings
- Not suitable for production environments
- No chain of trust

### 2. Generate Root CA + Server Certificate
Creates a new root Certificate Authority and uses it to sign a server certificate. This provides a proper certificate chain.

```bash
# Generate new root CA and server certificate
cargo run -- generate-cert --generate-ca --common-name server.example.com --ca-common-name "My Company Root CA"
```

**Generated files:**
- `cert.pem` - Server certificate
- `key.pem` - Server private key
- `cert.ca.pem` - Root CA certificate
- `key.ca.pem` - Root CA private key (keep secure!)
- `cert.crt` - Server certificate in CRT format

**Use cases:**
- Internal company networks
- Microservices communication
- Development environments that need proper certificate chains
- Testing certificate validation logic

**Security considerations:**
- Keep the root CA private key extremely secure
- Consider using hardware security modules (HSM) for production
- Implement proper key rotation policies

### 3. Use Existing Root CA
Uses an existing root CA to sign new server certificates. This is the most secure and production-ready approach.

```bash
# Generate server certificate signed by existing CA
cargo run -- generate-cert --with-ca --ca-cert /path/to/ca.pem --ca-key /path/to/ca_key.pem --common-name api.example.com
```

**Use cases:**
- Production environments
- Integration with existing PKI infrastructure
- Multiple certificates signed by the same CA
- Compliance with corporate security policies

## Command Line Options

### Basic Options
- `--cert-file <CERT_FILE>` - Output path for server certificate (default: cert.pem)
- `--key-file <KEY_FILE>` - Output path for server private key (default: key.pem)
- `--common-name <COMMON_NAME>` - Certificate common name/hostname (default: localhost)
- `--domains <DOMAINS>` - Additional Subject Alternative Names (comma-separated)

### Mode Selection (mutually exclusive)
- `--self-signed` - Generate self-signed certificate (default)
- `--with-ca` - Use existing root CA to sign certificate
- `--generate-ca` - Generate new root CA and server certificate

### CA Options
- `--ca-cert <CA_CERT>` - Path to existing root CA certificate (required with --with-ca)
- `--ca-key <CA_KEY>` - Path to existing root CA private key (required with --with-ca)
- `--ca-common-name <CA_COMMON_NAME>` - Common name for generated root CA (default: "Local Proxy Root CA")

## Examples

### Development Setup
```bash
# Simple self-signed certificate for localhost
cargo run -- generate-cert

# Self-signed certificate with multiple domains
cargo run -- generate-cert --common-name api.dev.local --domains "api.dev.local,localhost,127.0.0.1"
```

### Internal Company Network
```bash
# Generate root CA and server certificate for internal services
cargo run -- generate-cert --generate-ca \
  --common-name "internal.company.com" \
  --ca-common-name "Company Internal Root CA" \
  --cert-file internal_server.pem \
  --key-file internal_server_key.pem

# Generate additional certificates using the same CA
cargo run -- generate-cert --with-ca \
  --ca-cert internal_server.ca.pem \
  --ca-key internal_server_key.ca.pem \
  --common-name "api.internal.company.com" \
  --cert-file api_server.pem \
  --key-file api_server_key.pem
```

### Production Environment
```bash
# Use your organization's root CA
cargo run -- generate-cert --with-ca \
  --ca-cert /secure/path/to/company-root-ca.pem \
  --ca-key /secure/path/to/company-root-ca-key.pem \
  --common-name "prod.example.com" \
  --domains "prod.example.com,www.prod.example.com,api.prod.example.com" \
  --cert-file prod_server.pem \
  --key-file prod_server_key.pem
```

## File Structure

When using `--generate-ca` or `--with-ca` modes, the following files are created:

```
project/
├── cert.pem           # Server certificate
├── key.pem            # Server private key
├── cert.crt           # Server certificate (CRT format)
├── cert.ca.pem        # Root CA certificate (for client trust)
└── key.ca.pem         # Root CA private key (KEEP SECURE!)
```

## Certificate Validation

The system includes built-in validation for generated certificates:
- PEM format validation
- Private key format verification
- Certificate-key pair matching
- CA certificate validation

## Security Best Practices

### Root CA Security
1. **Secure Storage**: Store root CA private keys in secure, offline locations
2. **Access Control**: Limit access to root CA keys to authorized personnel only
3. **Backup**: Maintain secure backups of root CA materials
4. **Monitoring**: Log all root CA operations and monitor for unauthorized use

### Certificate Management
1. **Key Rotation**: Implement regular certificate renewal
2. **Revocation**: Maintain certificate revocation lists (CRL) or use OCSP
3. **Validity Periods**: Use appropriate certificate lifetimes (90-365 days for servers)
4. **Subject Alternative Names**: Include all necessary hostnames and IP addresses

### Deployment Considerations
1. **Certificate Distribution**: Securely distribute root CA certificates to clients
2. **Automated Renewal**: Implement automated certificate renewal processes
3. **Monitoring**: Monitor certificate expiration dates
4. **Testing**: Test certificate chains in staging environments

## Programming API

The certificate generation functionality is also available as a programmatic API:

```rust
use rrproxy::cert_gen::*;

// Self-signed certificate
let config = CertConfig::default();
let mode = CertGenerationMode::SelfSigned;
let result = generate_certificate_with_mode(&config, &mode)?;

// Generate root CA and server certificate
let ca_mode = CertGenerationMode::GenerateRootCa(RootCaConfig::default());
let ca_result = generate_certificate_with_mode(&config, &ca_mode)?;

// Use existing CA
let existing_ca_config = RootCaConfig {
    ca_cert_path: Some("ca.pem".to_string()),
    ca_key_path: Some("ca_key.pem".to_string()),
    ca_cert_config: CertConfig::default(),
};
let existing_ca_mode = CertGenerationMode::WithRootCa(existing_ca_config);
let signed_result = generate_certificate_with_mode(&config, &existing_ca_mode)?;
```

## Troubleshooting

### Common Issues

**Error: "CA certificate path not provided"**
- Ensure both `--ca-cert` and `--ca-key` are specified when using `--with-ca`

**Error: "Failed to read CA certificate file"**
- Check file paths and permissions
- Verify files exist and are readable

**Error: "Invalid CA certificate or key files"**
- Ensure CA files are in PEM format
- Verify certificate and key file integrity

**Error: "Failed to parse CA private key"**
- Check private key format (should be PEM)
- Ensure private key is not encrypted or provide decryption

### Debug Mode
Enable detailed logging for troubleshooting:
```bash
RUST_LOG=debug cargo run -- generate-cert --generate-ca --common-name test.local
```

## Testing

The implementation includes comprehensive tests covering all certificate generation modes:

```bash
# Run all certificate generation tests
cargo test cert_gen

# Run integration tests
cargo test --test test_certificate_generation_integration

# Run specific test
cargo test test_complete_certificate_generation_workflow
```

## Migration from Legacy Self-Signed Certificates

If you're currently using the old self-signed certificate generation, you can:

1. **Continue using self-signed** (default behavior unchanged):
   ```bash
   cargo run -- generate-cert --common-name your-domain.com
   ```

2. **Upgrade to CA-signed certificates**:
   ```bash
   # Generate CA and server certificate
   cargo run -- generate-cert --generate-ca --common-name your-domain.com
   
   # Use the generated CA for additional certificates
   cargo run -- generate-cert --with-ca --ca-cert cert.ca.pem --ca-key key.ca.pem --common-name api.your-domain.com
   ```

The new implementation maintains backward compatibility while providing enhanced security options for production use.
