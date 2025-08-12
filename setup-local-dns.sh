#!/bin/bash

# Setup local DNS for osint.local development

echo "🌐 Setting up local DNS for OSINT Platform..."

# Check if running as root for /etc/hosts modification
if [[ $EUID -eq 0 ]]; then
   echo "❌ Don't run this script as root - it will use sudo when needed"
   exit 1
fi

# Backup existing /etc/hosts
echo "💾 Creating backup of /etc/hosts..."
sudo cp /etc/hosts /etc/hosts.backup.$(date +%Y%m%d_%H%M%S)

# Add OSINT Platform entries to /etc/hosts
echo "📝 Adding OSINT Platform entries to /etc/hosts..."

# Check if entries already exist
if ! grep -q "osint.local" /etc/hosts; then
    echo "# OSINT Platform - Enterprise OSINT Development" | sudo tee -a /etc/hosts
    echo "127.0.0.1    osint.local" | sudo tee -a /etc/hosts
    echo "127.0.0.1    api.osint.local" | sudo tee -a /etc/hosts
    echo "127.0.0.1    flower.osint.local" | sudo tee -a /etc/hosts
    echo "" | sudo tee -a /etc/hosts
    echo "✅ DNS entries added successfully"
else
    echo "ℹ️  OSINT Platform DNS entries already exist"
fi

# Display current OSINT entries
echo ""
echo "📋 Current OSINT Platform DNS entries:"
grep -A 5 "OSINT Platform" /etc/hosts || true

echo ""
echo "🎯 OSINT Platform URLs:"
echo "  🌐 Main Interface:    https://osint.local/"
echo "  🔌 API Endpoint:      https://api.osint.local/"
echo "  📊 API Health:        https://osint.local/health"
echo "  📈 Metrics:           https://osint.local/metrics"
echo "  📚 API Documentation: https://osint.local/docs"

echo ""
echo "🔧 Next steps:"
echo "  1. Install the CA certificate to trust self-signed certificates"
echo "  2. Access the platform at https://osint.local/"
echo ""

# Check if CA certificate exists and provide installation instructions
if [[ -f "ssl/server-cert.pem" ]]; then
    echo "📜 To install the CA certificate (macOS):"
    echo "   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ssl/server-cert.pem"
    echo ""
    echo "📜 To install the CA certificate (Linux):"
    echo "   sudo cp ssl/server-cert.pem /usr/local/share/ca-certificates/osint-local.crt"
    echo "   sudo update-ca-certificates"
    echo ""
fi

echo "✅ Local DNS setup complete!"