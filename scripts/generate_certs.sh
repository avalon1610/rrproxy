#!/bin/bash

# Certificate Generation Script for RRProxy (Linux/macOS)
# This script generates self-signed certificates for HTTPS proxy functionality

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERT_DIR="$PROJECT_ROOT"

echo "🔐 Generating certificates for RRProxy..."
echo "📁 Project root: $PROJECT_ROOT"
echo "📁 Certificates will be saved to: $CERT_DIR"

# Check if OpenSSL is installed
if ! command -v openssl &> /dev/null; then
    echo "❌ OpenSSL is not installed. Please install it first:"
    echo "   Ubuntu/Debian: sudo apt-get install openssl"
    echo "   CentOS/RHEL:   sudo yum install openssl"
    echo "   macOS:         brew install openssl"
    exit 1
fi

# Certificate configuration
CERT_SUBJECT="/C=US/ST=CA/L=San Francisco/O=RRProxy/OU=Development/CN=localhost"
KEY_SIZE=2048
VALIDITY_DAYS=365

echo "📋 Certificate configuration:"
echo "   Subject: $CERT_SUBJECT"
echo "   Key size: $KEY_SIZE bits"
echo "   Validity: $VALIDITY_DAYS days"

# Backup existing certificates if they exist
if [ -f "$CERT_DIR/cert.pem" ] || [ -f "$CERT_DIR/key.pem" ]; then
    BACKUP_DIR="$CERT_DIR/cert_backup_$(date +%Y%m%d_%H%M%S)"
    echo "🔄 Backing up existing certificates to: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    
    [ -f "$CERT_DIR/cert.pem" ] && cp "$CERT_DIR/cert.pem" "$BACKUP_DIR/"
    [ -f "$CERT_DIR/key.pem" ] && cp "$CERT_DIR/key.pem" "$BACKUP_DIR/"
    [ -f "$CERT_DIR/cert.crt" ] && cp "$CERT_DIR/cert.crt" "$BACKUP_DIR/"
    
    echo "✅ Backup completed"
fi

# Generate private key
echo "🔑 Generating private key..."
openssl genrsa -out "$CERT_DIR/key.pem" $KEY_SIZE

# Generate certificate signing request
echo "📝 Generating certificate signing request..."
openssl req -new -key "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.csr" -subj "$CERT_SUBJECT"

# Create extensions file for Subject Alternative Names
cat > "$CERT_DIR/cert.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate self-signed certificate
echo "📜 Generating self-signed certificate..."
openssl x509 -req -in "$CERT_DIR/cert.csr" -signkey "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
    -days $VALIDITY_DAYS -extensions v3_req -extfile "$CERT_DIR/cert.ext"

# Also create a .crt version for compatibility
cp "$CERT_DIR/cert.pem" "$CERT_DIR/cert.crt"

# Clean up temporary files
rm -f "$CERT_DIR/cert.csr" "$CERT_DIR/cert.ext"

# Set appropriate permissions
chmod 600 "$CERT_DIR/key.pem"
chmod 644 "$CERT_DIR/cert.pem" "$CERT_DIR/cert.crt"

echo "✅ Certificates generated successfully!"
echo ""
echo "📁 Generated files:"
echo "   🔑 Private key: $CERT_DIR/key.pem"
echo "   📜 Certificate: $CERT_DIR/cert.pem"
echo "   📜 Certificate (copy): $CERT_DIR/cert.crt"
echo ""
echo "📋 Certificate information:"
openssl x509 -in "$CERT_DIR/cert.pem" -text -noout | grep -A 5 "Subject:"
openssl x509 -in "$CERT_DIR/cert.pem" -text -noout | grep -A 5 "Not Before"
echo ""
echo "🔍 To verify the certificate:"
echo "   openssl x509 -in $CERT_DIR/cert.pem -text -noout"
echo ""
echo "⚠️  Note: These are self-signed certificates for development use only."
echo "   For production, use certificates from a trusted Certificate Authority."
echo ""
echo "🚀 You can now run RRProxy with HTTPS support!"
