# RRProxy Deployment Scripts

This directory contains scripts to help deploy RRProxy and generate SSL/TLS certificates for HTTPS proxy functionality.

## Files

### Certificate Generation Scripts

- **`generate_certs.sh`** - Linux/macOS certificate generation script
- **`generate_certs.ps1`** - Windows PowerShell certificate generation script  
- **`generate_certs.bat`** - Windows batch file (calls PowerShell script)

## Usage

### Linux/macOS

```bash
cd scripts
chmod +x generate_certs.sh
./generate_certs.sh
```

### Windows (PowerShell)

```powershell
cd scripts
powershell -ExecutionPolicy Bypass -File generate_certs.ps1
```

### Windows (Command Prompt)

```cmd
cd scripts
generate_certs.bat
```

## Requirements

### Linux/macOS
- OpenSSL (usually pre-installed)
- Bash shell

### Windows
- OpenSSL for Windows
- PowerShell (built-in on Windows 7+)

## Certificate Details

The scripts generate self-signed certificates with:
- 2048-bit RSA private key
- Subject Alternative Names for localhost and 127.0.0.1
- 365 days validity (configurable)
- Compatible with modern browsers and HTTP clients

## Generated Files

- `../cert.pem` - Certificate in PEM format
- `../cert.crt` - Certificate copy (same as .pem)
- `../key.pem` - Private key in PEM format

## Security Notes

⚠️ **Important**: These are self-signed certificates for development/testing only.

For production use:
- Use certificates from a trusted Certificate Authority
- Keep private keys secure and never share them
- Consider using Let's Encrypt for free trusted certificates

## Troubleshooting

### OpenSSL Not Found

**Linux/Ubuntu/Debian:**
```bash
sudo apt-get install openssl
```

**CentOS/RHEL:**
```bash
sudo yum install openssl
```

**macOS:**
```bash
brew install openssl
```

**Windows:**
- Download from [OpenSSL for Windows](https://slproweb.com/products/Win32OpenSSL.html)
- Or install via Chocolatey: `choco install openssl`
- Or install via winget: `winget install OpenSSL.OpenSSL`

### Permission Issues

**Linux/macOS:**
Make sure the script is executable:
```bash
chmod +x generate_certs.sh
```

**Windows:**
Run PowerShell as Administrator if you encounter permission issues.

### Certificate Trust

To trust the generated certificates in your browser:
1. Import `cert.pem` into your browser's certificate store
2. Or add it to your system's trusted certificate authorities
3. Or use the `-k` flag with curl to ignore certificate errors during testing

## Example Usage

After running the certificate generation script, you can start RRProxy with HTTPS support:

```bash
# Start remote proxy (on server outside firewall)
cargo run --release -- remote --listen-addr "0.0.0.0:8081"

# Start local proxy (on client inside firewall)  
cargo run --release -- local --listen-addr "127.0.0.1:8080" --remote-addr "https://server-ip:8081"
```

Then configure your applications to use `127.0.0.1:8080` as HTTP/HTTPS proxy.
