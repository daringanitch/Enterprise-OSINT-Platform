#!/bin/bash

# Generate SSL certificates for local development
# This script creates self-signed certificates for osint.local

set -e

# Create SSL directory
mkdir -p ssl
cd ssl

echo "🔐 Generating SSL certificates for osint.local..."

# Create certificate authority (CA)
echo "📜 Creating Certificate Authority..."
openssl genrsa -out ca-key.pem 2048
openssl req -new -x509 -days 365 -key ca-key.pem -out ca-cert.pem -subj "/C=US/ST=Development/L=Local/O=Enterprise OSINT/OU=Development/CN=OSINT-CA"

# Create server private key
echo "🔑 Creating server private key..."
openssl genrsa -out server-key.pem 2048

# Create certificate signing request
echo "📝 Creating certificate signing request..."
openssl req -new -key server-key.pem -out server.csr -subj "/C=US/ST=Development/L=Local/O=Enterprise OSINT/OU=Development/CN=osint.local"

# Create certificate extensions file
cat > server-extensions.conf << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = osint.local
DNS.2 = *.osint.local
DNS.3 = api.osint.local
DNS.4 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate server certificate
echo "🏆 Generating server certificate..."
openssl x509 -req -days 365 -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -out server-cert.pem -extensions v3_req -extfile server-extensions.conf -CAcreateserial

# Create combined certificate for nginx
echo "📦 Creating combined certificate..."
cat server-cert.pem > osint-local.crt

# Set proper permissions
chmod 600 *-key.pem
chmod 644 *.crt *.pem

echo "✅ SSL certificates generated successfully!"
echo "📁 Certificates location: $(pwd)"
echo ""
echo "📋 Files created:"
echo "  - ca-cert.pem (Certificate Authority)"
echo "  - server-cert.pem (Server certificate)"
echo "  - server-key.pem (Private key)"
echo "  - osint-local.crt (Combined certificate for nginx)"