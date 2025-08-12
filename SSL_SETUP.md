# 🔐 SSL/TLS Setup for Enterprise OSINT Platform

## Overview

The Enterprise OSINT Platform now supports HTTPS/SSL access with self-signed certificates for local development.

## 📋 Current Configuration

### SSL Certificates Generated
- **Location**: `ssl/`
- **Certificate**: `server-cert.pem` (self-signed)
- **Private Key**: `server-key.pem`
- **Domains**: 
  - `osint.local`
  - `*.osint.local`
  - `api.osint.local`
  - `localhost`

### Kubernetes SSL Configuration
- **TLS Secret**: `osint-local-tls` (in `osint-platform` namespace)
- **SSL Ingress**: `osint-ssl-ingress` (HTTPS with TLS termination)
- **HTTP Ingress**: `osint-localhost-ingress` (HTTP for localhost convenience)

## 🌐 Access Methods

### Method 1: HTTP via localhost (Ready Now)
- **Frontend**: http://localhost/
- **API Health**: http://localhost/health
- **API Docs**: http://localhost/docs
- **Metrics**: http://localhost/metrics

### Method 2: HTTPS via osint.local (Requires DNS Setup)
To use custom domains with HTTPS:

1. **Add DNS entries to /etc/hosts**:
   ```bash
   # Add these lines to /etc/hosts
   127.0.0.1    osint.local
   127.0.0.1    api.osint.local
   127.0.0.1    flower.osint.local
   ```

2. **Install SSL certificate (optional, to avoid browser warnings)**:

   **macOS**:
   ```bash
   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ssl/server-cert.pem
   ```

   **Linux**:
   ```bash
   sudo cp ssl/server-cert.pem /usr/local/share/ca-certificates/osint-local.crt
   sudo update-ca-certificates
   ```

3. **Access via HTTPS**:
   - **Frontend**: https://osint.local/
   - **API**: https://api.osint.local/
   - **API Health**: https://osint.local/health
   - **Metrics**: https://osint.local/metrics
   - **API Docs**: https://osint.local/docs

## 🔧 Technical Details

### Ingress Configuration
- **SSL Ingress**: Host-based routing for `osint.local` and `api.osint.local`
- **HTTP Ingress**: Catch-all routing for `localhost`
- **TLS**: TLS 1.2 and TLS 1.3 enabled
- **SSL Redirect**: HTTPS enforced for domain names, HTTP allowed for localhost

### Certificate Details
- **Type**: Self-signed certificate
- **Algorithm**: RSA 2048-bit
- **Validity**: 365 days
- **Subject Alternative Names**: osint.local, *.osint.local, api.osint.local, localhost

## 🚀 Current Status

✅ **SSL certificates generated**
✅ **Kubernetes TLS secret created**
✅ **SSL ingress deployed**
✅ **HTTP localhost access working**
⏳ **DNS setup required for HTTPS domain access**

## 🔄 Next Steps

1. **Manual DNS Setup**: Add entries to `/etc/hosts` for domain-based access
2. **Certificate Installation**: Install CA certificate to avoid browser warnings
3. **Production**: Replace self-signed certificates with proper CA-signed certificates

## 📊 Performance

- **HTTP Response Time**: ~2-10ms
- **SSL Handshake Overhead**: ~5-15ms additional
- **Certificate Validation**: Self-signed (browser warning expected without CA installation)