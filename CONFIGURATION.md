# Enterprise OSINT Platform - Configuration Reference

Complete configuration guide for the Enterprise OSINT Platform including the in-app service configuration UI, environment variables, API keys, Kubernetes secrets, and deployment options.

## Table of Contents
1. [Overview](#overview)
2. [In-App Service Configuration (Recommended)](#in-app-service-configuration-recommended)
3. [Environment Variables](#environment-variables)
4. [API Keys Configuration](#api-keys-configuration)
5. [Kubernetes Secrets](#kubernetes-secrets)
6. [Database Configuration](#database-configuration)
7. [MCP Server Configuration](#mcp-server-configuration)
8. [Security Configuration](#security-configuration)
9. [Performance Tuning](#performance-tuning)
10. [Monitoring Configuration](#monitoring-configuration)

---

## Overview

The Enterprise OSINT Platform is designed to be **immediately useful with zero configuration**. Nine intelligence services work out of the box for free. Additional services can be unlocked by adding optional API keys — most of which have free tiers.

### Configuration Hierarchy
1. **In-App Settings UI** (recommended) — point-and-click, persisted to `service_config.json`
2. **Environment Variables** — for CI/CD pipelines and Kubernetes deployments
3. **Kubernetes Secrets** — for production deployments
4. **Default Values** — built-in fallbacks

---

## In-App Service Configuration (Recommended)

The easiest way to configure the platform is through the **Settings** page in the web UI (`/settings`). No file editing or environment variable knowledge required.

### What Works Without Any API Keys

The following services are active immediately after installation:

| Service | Category | What It Provides |
|---|---|---|
| DNS Resolution | Network | A, MX, TXT, NS, CNAME records; subdomain enumeration |
| WHOIS Lookup | Network | Registrar, registration dates, name servers |
| Certificate Transparency (crt.sh) | Network | Subdomain discovery via SSL cert logs |
| IP Geolocation (ip-api.com) | Network | Country, city, ISP, ASN — 45 req/min |
| MalwareBazaar (abuse.ch) | Threat | Malware hash lookups and family classification |
| ThreatFox (abuse.ch) | Threat | Community IOC database (IPs, domains, hashes) |
| URLScan.io (basic) | Threat | URL sandbox scans and verdicts |
| Have I Been Pwned (password) | Breach | k-anonymity password breach check |
| GitHub (unauthenticated) | Social | Public repo and profile searches — 10 req/min |

### Adding Optional API Keys (UI)

1. Navigate to **Settings → Services** in the web UI
2. Find the service you want to configure
3. Click the **expand arrow (›)** on the service card
4. Paste your API key and click **Save Key**
5. Click **Test Connection** to verify the key works

Keys are stored in `$APP_DATA_DIR/service_config.json` and loaded automatically on restart.

### Services Available With a Free API Key

All of these services have a **free tier** — sign-up takes under 2 minutes:

| Service | Free Tier | Sign Up |
|---|---|---|
| VirusTotal | 500 lookups/day, 4 req/min | https://www.virustotal.com/gui/join-us |
| AbuseIPDB | 1,000 checks/day | https://www.abuseipdb.com/register |
| AlienVault OTX | Unlimited community lookups | https://otx.alienvault.com/accounts/signup |
| GreyNoise Community | 50 req/day | https://www.greynoise.io/signup |
| Have I Been Pwned | Rate-limited breach search | https://haveibeenpwned.com/API/Key |
| Shodan | 2 query credits/month | https://account.shodan.io/register |
| Censys | 250 queries/month | https://search.censys.io/register |
| GitHub (authenticated) | 30 req/min | https://github.com/settings/tokens |
| URLScan.io (full) | 5,000 scans/day | https://urlscan.io/user/signup |

### Optional Paid Services

| Service | Cost | Purpose |
|---|---|---|
| OpenAI (GPT-4) | ~$0.01–0.03/investigation | AI summaries, threat profiling, narrative generation |
| Twitter / X | $100/month Basic | Social intelligence and network analysis |
| Dehashed | From $5.49/month | Breached credential search (billions of records) |
| Shodan Membership | From $49/month | Full port scan data, vulnerability tracking, alerts |

### Operating Modes

Switch between modes on the **Settings → Mode & General** tab:

- **Demo Mode** (default) — All data is synthetic. Safe to explore, no API calls made, no rate limits consumed.
- **Live Mode** — Real intelligence gathering. Free services work immediately; configured API keys are used.

### service_config.json

Keys saved via the UI are stored in `$APP_DATA_DIR/service_config.json` (default: `/app/data/service_config.json`). This file is loaded at startup and keys are injected into the process environment automatically.

```json
{
  "services": {
    "virustotal": { "enabled": true },
    "dns": { "enabled": true }
  },
  "api_keys": {
    "VIRUSTOTAL_API_KEY": "your-key-here"
  },
  "updated_at": "2026-02-25T00:00:00"
}
```

> **Security note:** The config file contains plaintext API keys. Ensure `$APP_DATA_DIR` is on a volume with appropriate filesystem permissions (readable only by the app process). For production Kubernetes deployments, prefer environment variables or Vault integration instead.

---

---

## Environment Variables

### Core Backend Configuration

#### **Required Variables**
```bash
# Database Connection
POSTGRES_URL=postgresql://postgres:password@postgresql:5432/osint_audit
POSTGRES_HOST=postgresql
POSTGRES_PORT=5432
POSTGRES_USER=postgres
POSTGRES_PASSWORD=secure_password
POSTGRES_DB=osint_audit

# JWT Security
JWT_SECRET_KEY=your-secure-secret-key-change-in-production
JWT_ACCESS_TOKEN_EXPIRES=3600  # seconds (1 hour)
JWT_ALGORITHM=HS256

# Flask Configuration
FLASK_ENV=production
FLASK_DEBUG=false
LOG_LEVEL=INFO
```

#### **MCP Server URLs (Internal Kubernetes)**
```bash
# Enhanced MCP Servers
MCP_INFRASTRUCTURE_URL=http://mcp-infrastructure-enhanced:8021
MCP_THREAT_URL=http://mcp-threat-enhanced:8020
MCP_AI_URL=http://mcp-technical-enhanced:8050
MCP_SOCIAL_URL=http://mcp-social-enhanced:8010
MCP_FINANCIAL_URL=http://mcp-financial-enhanced:8040

# MCP Request Timeouts
MCP_REQUEST_TIMEOUT=300  # seconds
MCP_CONNECTION_TIMEOUT=30  # seconds
MCP_MAX_RETRIES=3
```

#### **Optional Variables**
```bash
# Vault Integration (optional)
VAULT_ADDR=http://vault:8200
VAULT_TOKEN=dev-only-token
VAULT_MOUNT_PATH=secret

# Application Settings
APP_NAME=Enterprise OSINT Platform
APP_VERSION=2.0.0
WORKER_PROCESSES=4
WORKER_TIMEOUT=300

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=100
RATE_LIMIT_PER_HOUR=1000

# Investigation Settings
MAX_CONCURRENT_INVESTIGATIONS=10
DEFAULT_INVESTIGATION_TIMEOUT=3600  # 1 hour
AUTO_CLEANUP_INVESTIGATIONS=true
INVESTIGATION_RETENTION_DAYS=90
```

### Frontend Configuration

```bash
# API Endpoints
REACT_APP_API_URL=http://localhost:5000
REACT_APP_WS_URL=ws://localhost:5000

# Application Settings
REACT_APP_NAME=Enterprise OSINT Platform
REACT_APP_VERSION=2.0.0

# Feature Flags
REACT_APP_ENABLE_ANALYTICS=false
REACT_APP_ENABLE_DEBUG=false
REACT_APP_MAX_FILE_SIZE=10485760  # 10MB
```

---

## API Keys Configuration

### External Service API Keys

#### **Threat Intelligence APIs**
```bash
# VirusTotal (highly recommended)
VIRUSTOTAL_API_KEY=your-virustotal-api-key
VIRUSTOTAL_RATE_LIMIT=4  # requests per minute for free tier

# AbuseIPDB (recommended)
ABUSEIPDB_API_KEY=your-abuseipdb-api-key
ABUSEIPDB_RATE_LIMIT=1000  # requests per day for free tier

# Shodan (recommended)
SHODAN_API_KEY=your-shodan-api-key
SHODAN_RATE_LIMIT=100  # requests per month for free tier

# AlienVault OTX (free)
ALIENVAULT_OTX_API_KEY=your-otx-api-key

# URLScan.io (optional)
URLSCAN_API_KEY=your-urlscan-api-key

# Hybrid Analysis (optional)
HYBRID_ANALYSIS_API_KEY=your-hybrid-analysis-key
```

#### **AI Enhancement APIs**
```bash
# OpenAI (for AI analyzer)
OPENAI_API_KEY=your-openai-api-key
OPENAI_MODEL=gpt-4-turbo-preview
OPENAI_MAX_TOKENS=4000
OPENAI_TEMPERATURE=0.3
```

#### **Social Media APIs**
```bash
# Twitter/X API v2 (optional)
TWITTER_BEARER_TOKEN=your-twitter-bearer-token
TWITTER_API_KEY=your-twitter-api-key
TWITTER_API_SECRET=your-twitter-api-secret

# Reddit API (optional)
REDDIT_CLIENT_ID=your-reddit-client-id
REDDIT_CLIENT_SECRET=your-reddit-client-secret
REDDIT_USER_AGENT=Enterprise-OSINT-Platform/2.0
```

#### **Financial Intelligence APIs**
```bash
# Alpha Vantage (optional)
ALPHA_VANTAGE_API_KEY=your-alpha-vantage-key

# SEC API (optional)
SEC_API_KEY=your-sec-api-key

# Company information APIs
COMPANY_API_KEY=your-company-api-key
```

### API Key Priority and Fallbacks

The platform gracefully handles missing API keys:

1. **Required APIs**: None - all external APIs are optional
2. **Enhanced Features**: Missing keys disable specific capabilities
3. **Fallback Behavior**: Simulated/demo data when APIs unavailable

---

## Kubernetes Secrets

### Creating API Keys Secret

```bash
# Create comprehensive API keys secret
kubectl create secret generic osint-api-keys \
  --namespace=osint-platform \
  --from-literal=virustotal-api-key="${VIRUSTOTAL_API_KEY}" \
  --from-literal=abuseipdb-api-key="${ABUSEIPDB_API_KEY}" \
  --from-literal=shodan-api-key="${SHODAN_API_KEY}" \
  --from-literal=openai-api-key="${OPENAI_API_KEY}" \
  --from-literal=twitter-bearer-token="${TWITTER_BEARER_TOKEN}" \
  --from-literal=reddit-client-id="${REDDIT_CLIENT_ID}" \
  --from-literal=reddit-client-secret="${REDDIT_CLIENT_SECRET}" \
  --from-literal=alpha-vantage-api-key="${ALPHA_VANTAGE_API_KEY}"
```

### Database Credentials Secret

```bash
# Create database secret
kubectl create secret generic postgresql-secret \
  --namespace=osint-platform \
  --from-literal=POSTGRES_PASSWORD="${POSTGRES_PASSWORD}" \
  --from-literal=POSTGRES_USER="${POSTGRES_USER}"
```

### JWT Secret

```bash
# Create JWT secret
kubectl create secret generic jwt-secret \
  --namespace=osint-platform \
  --from-literal=JWT_SECRET_KEY="${JWT_SECRET_KEY}"
```

### Secret Manifest Example

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: osint-api-keys
  namespace: osint-platform
type: Opaque
data:
  virustotal-api-key: <base64-encoded-key>
  abuseipdb-api-key: <base64-encoded-key>
  shodan-api-key: <base64-encoded-key>
  openai-api-key: <base64-encoded-key>
---
apiVersion: v1
kind: Secret
metadata:
  name: postgresql-secret
  namespace: osint-platform
type: Opaque
data:
  POSTGRES_PASSWORD: <base64-encoded-password>
  POSTGRES_USER: <base64-encoded-username>
```

---

## Database Configuration

### PostgreSQL Configuration

#### **Production Database Setup**
```bash
# Environment variables for PostgreSQL
POSTGRES_VERSION=15.5
POSTGRES_SHARED_BUFFERS=256MB
POSTGRES_EFFECTIVE_CACHE_SIZE=1GB
POSTGRES_MAINTENANCE_WORK_MEM=64MB
POSTGRES_CHECKPOINT_COMPLETION_TARGET=0.9
POSTGRES_WAL_BUFFERS=16MB
POSTGRES_DEFAULT_STATISTICS_TARGET=100
POSTGRES_RANDOM_PAGE_COST=1.1
POSTGRES_EFFECTIVE_IO_CONCURRENCY=200
```

#### **Connection Pool Settings**
```bash
# Backend connection pooling
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=10
DB_POOL_TIMEOUT=30
DB_POOL_RECYCLE=3600
DB_POOL_PRE_PING=true
```

#### **Database Schema**
The platform automatically creates the required schema:

```sql
-- Main database
CREATE DATABASE osint_audit;

-- Audit schema for compliance
CREATE SCHEMA IF NOT EXISTS audit;

-- Required tables (auto-created)
-- audit.events - System audit trail
-- audit.investigations - Investigation records
-- audit.api_key_usage - API consumption tracking
-- audit.risk_assessments - Risk scoring
-- audit.compliance_assessments - Compliance validation
-- audit.system_metrics - Performance metrics
```

#### **Backup Configuration**
```bash
# Automated backup settings
POSTGRES_BACKUP_ENABLED=true
POSTGRES_BACKUP_SCHEDULE="0 2 * * *"  # Daily at 2 AM
POSTGRES_BACKUP_RETENTION_DAYS=30
POSTGRES_BACKUP_COMPRESSION=true
```

---

## MCP Server Configuration

### Individual MCP Server Settings

#### **Infrastructure Advanced MCP (8021)**
```bash
# Server configuration
INFRASTRUCTURE_MCP_HOST=0.0.0.0
INFRASTRUCTURE_MCP_PORT=8021
INFRASTRUCTURE_MCP_WORKERS=2
INFRASTRUCTURE_MCP_TIMEOUT=300

# Feature toggles
ENABLE_CERTIFICATE_TRANSPARENCY=true
ENABLE_PASSIVE_DNS=true
ENABLE_ASN_LOOKUP=true
ENABLE_PORT_SCANNING=true
ENABLE_WEB_TECH_DETECTION=true

# Rate limiting
INFRASTRUCTURE_RATE_LIMIT=100  # requests per minute
INFRASTRUCTURE_CONCURRENT_REQUESTS=10
```

#### **Threat Aggregator MCP (8020)**
```bash
# Server configuration
THREAT_MCP_HOST=0.0.0.0
THREAT_MCP_PORT=8020
THREAT_MCP_WORKERS=1
THREAT_MCP_TIMEOUT=300

# Cache settings
THREAT_CACHE_TTL=3600  # 1 hour
THREAT_CACHE_SIZE=1000  # entries

# Source priorities (1-10, higher = more trusted)
VIRUSTOTAL_PRIORITY=9
ABUSEIPDB_PRIORITY=8
SHODAN_PRIORITY=7
OTX_PRIORITY=6
```

#### **AI Analyzer MCP (8050)**
```bash
# Server configuration
AI_MCP_HOST=0.0.0.0
AI_MCP_PORT=8050
AI_MCP_WORKERS=1
AI_MCP_TIMEOUT=600  # Longer timeout for AI processing

# OpenAI settings
OPENAI_MODEL=gpt-4-turbo-preview
OPENAI_MAX_TOKENS=4000
OPENAI_TEMPERATURE=0.3
OPENAI_REQUEST_TIMEOUT=120
```

### MCP Health Check Configuration

```bash
# Health check settings
MCP_HEALTH_CHECK_INTERVAL=30  # seconds
MCP_HEALTH_CHECK_TIMEOUT=10   # seconds
MCP_HEALTH_CHECK_RETRIES=3
MCP_HEALTH_CHECK_BACKOFF=2    # exponential backoff multiplier
```

---

## Security Configuration

### TLS/SSL Configuration

#### **Certificate Management**
```bash
# TLS settings
TLS_ENABLED=true
TLS_CERT_PATH=/etc/ssl/certs/osint-platform.crt
TLS_KEY_PATH=/etc/ssl/private/osint-platform.key
TLS_CA_PATH=/etc/ssl/certs/ca.crt

# TLS versions
TLS_MIN_VERSION=1.2
TLS_MAX_VERSION=1.3
TLS_CIPHERS=ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256
```

#### **CORS Configuration**
```bash
# CORS settings
CORS_ENABLED=true
CORS_ORIGINS=http://localhost:8080,https://osint.yourdomain.com
CORS_METHODS=GET,POST,DELETE,OPTIONS
CORS_HEADERS=Authorization,Content-Type,X-Requested-With
CORS_CREDENTIALS=true
CORS_MAX_AGE=86400
```

#### **Security Headers**
```bash
# Security headers
SECURITY_HEADERS_ENABLED=true
HSTS_MAX_AGE=31536000
HSTS_INCLUDE_SUBDOMAINS=true
CSP_ENABLED=true
CSP_POLICY="default-src 'self'; script-src 'self' 'unsafe-inline'"
X_FRAME_OPTIONS=DENY
X_CONTENT_TYPE_OPTIONS=nosniff
```

### Authentication Configuration

#### **JWT Settings**
```bash
# JWT configuration
JWT_SECRET_KEY=your-very-secure-secret-key-256-bits-minimum
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRES=3600    # 1 hour
JWT_REFRESH_TOKEN_EXPIRES=604800 # 7 days
JWT_ISSUER=enterprise-osint-platform
JWT_AUDIENCE=osint-api
```

#### **Password Policy**
```bash
# Password requirements
PASSWORD_MIN_LENGTH=8
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_NUMBERS=true
PASSWORD_REQUIRE_SPECIAL=true
PASSWORD_MAX_AGE_DAYS=90
PASSWORD_HISTORY_COUNT=5
```

#### **Session Management**
```bash
# Session settings
SESSION_TIMEOUT=3600          # 1 hour
SESSION_CONCURRENT_LIMIT=5    # Max sessions per user
SESSION_CLEANUP_INTERVAL=300  # 5 minutes
REMEMBER_ME_DURATION=604800   # 7 days
```

---

## Performance Tuning

### Application Performance

#### **Backend Optimization**
```bash
# Gunicorn settings
GUNICORN_WORKERS=4
GUNICORN_THREADS=2
GUNICORN_WORKER_CLASS=sync
GUNICORN_WORKER_TIMEOUT=300
GUNICORN_KEEPALIVE=2
GUNICORN_MAX_REQUESTS=1000
GUNICORN_MAX_REQUESTS_JITTER=100

# Connection pooling
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=10
DB_POOL_TIMEOUT=30
```

#### **Caching Configuration**
```bash
# Redis caching
REDIS_ENABLED=true
REDIS_URL=redis://osint-platform-redis-master:6379
REDIS_TTL=3600           # 1 hour default TTL
REDIS_MAX_CONNECTIONS=50
REDIS_CONNECTION_TIMEOUT=10

# Cache strategies
CACHE_INVESTIGATION_RESULTS=true
CACHE_MCP_RESPONSES=true
CACHE_USER_SESSIONS=true
CACHE_SYSTEM_STATUS=true
```

#### **Request Optimization**
```bash
# Request handling
MAX_REQUEST_SIZE=10485760      # 10MB
REQUEST_TIMEOUT=300            # 5 minutes
SLOW_QUERY_THRESHOLD=1000      # 1 second
CONNECTION_POOL_SIZE=20
```

### Resource Limits

#### **Kubernetes Resource Requests/Limits**
```yaml
# Backend resources
resources:
  requests:
    memory: "512Mi"
    cpu: "200m"
  limits:
    memory: "1Gi"
    cpu: "1000m"

# MCP server resources
resources:
  requests:
    memory: "256Mi"
    cpu: "100m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

---

## Monitoring Configuration

### Application Metrics

#### **Prometheus Integration**
```bash
# Metrics collection
METRICS_ENABLED=true
METRICS_PORT=9090
METRICS_PATH=/metrics
METRICS_NAMESPACE=osint_platform

# Custom metrics
TRACK_INVESTIGATION_DURATION=true
TRACK_API_RESPONSE_TIMES=true
TRACK_MCP_PERFORMANCE=true
TRACK_ERROR_RATES=true
```

#### **Health Checks**
```bash
# Health check endpoints
HEALTH_CHECK_ENABLED=true
HEALTH_CHECK_PATH=/health
HEALTH_CHECK_DEEP=true        # Include component checks
HEALTH_CHECK_TIMEOUT=30       # seconds
```

### Logging Configuration

#### **Log Levels and Formats**
```bash
# Logging configuration
LOG_LEVEL=INFO                # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FORMAT=json              # json, text
LOG_FILE=/var/log/osint/app.log
LOG_MAX_SIZE=100MB
LOG_BACKUP_COUNT=5
LOG_ROTATION=daily

# Component-specific logging
LOG_LEVEL_DATABASE=WARNING
LOG_LEVEL_MCP=INFO
LOG_LEVEL_AUTH=INFO
LOG_LEVEL_INVESTIGATIONS=DEBUG
```

#### **Audit Logging**
```bash
# Audit trail configuration
AUDIT_ENABLED=true
AUDIT_LOG_ALL_REQUESTS=false
AUDIT_LOG_AUTHENTICATION=true
AUDIT_LOG_INVESTIGATIONS=true
AUDIT_LOG_DATA_ACCESS=true
AUDIT_LOG_ADMIN_ACTIONS=true
AUDIT_RETENTION_DAYS=2555    # 7 years for compliance
```

### Error Tracking

#### **Error Monitoring**
```bash
# Error tracking
ERROR_TRACKING_ENABLED=true
ERROR_REPORTING_URL=https://your-error-tracking-service.com
ERROR_SAMPLE_RATE=1.0
ERROR_ENVIRONMENT=production

# Alert thresholds
ERROR_RATE_THRESHOLD=0.05     # 5% error rate
RESPONSE_TIME_THRESHOLD=5000  # 5 seconds
MCP_FAILURE_THRESHOLD=0.1     # 10% MCP failure rate
```

---

## Configuration Templates

### Development Environment

```bash
# .env.development
FLASK_ENV=development
FLASK_DEBUG=true
LOG_LEVEL=DEBUG

# Use local services
POSTGRES_URL=postgresql://postgres:password@localhost:5432/osint_audit
MCP_INFRASTRUCTURE_URL=http://localhost:8021
MCP_THREAT_URL=http://localhost:8020

# Simplified security for development
JWT_SECRET_KEY=dev-secret-key
CORS_ORIGINS=http://localhost:3000,http://localhost:8080

# Optional API keys
VIRUSTOTAL_API_KEY=your-dev-key
OPENAI_API_KEY=your-dev-key
```

### Production Environment

```bash
# .env.production
FLASK_ENV=production
FLASK_DEBUG=false
LOG_LEVEL=INFO

# Production database
POSTGRES_URL=postgresql://osint_user:secure_password@prod-db:5432/osint_audit

# Internal Kubernetes URLs
MCP_INFRASTRUCTURE_URL=http://mcp-infrastructure-enhanced:8021
MCP_THREAT_URL=http://mcp-threat-enhanced:8020

# Strong security
JWT_SECRET_KEY=your-very-secure-production-key-256-bits
CORS_ORIGINS=https://osint.yourdomain.com

# Production API keys from secrets
# (Configure via Kubernetes secrets)
```

### Testing Environment

```bash
# .env.testing
FLASK_ENV=testing
FLASK_DEBUG=false
LOG_LEVEL=WARNING

# Test database
POSTGRES_URL=postgresql://test_user:test_pass@test-db:5432/osint_test

# Mock MCP servers
USE_MOCK_MCP_SERVERS=true
MOCK_INVESTIGATION_DURATION=10  # seconds

# Test security
JWT_SECRET_KEY=test-secret-key
DISABLE_RATE_LIMITING=true
```

---

## Configuration Validation

### Startup Checks

The platform performs these validation checks on startup:

1. **Database Connectivity**: Verify PostgreSQL connection
2. **Required Environment Variables**: Check all required vars are set
3. **JWT Secret**: Ensure JWT_SECRET_KEY is sufficiently secure
4. **MCP Server Health**: Test connectivity to all MCP servers
5. **API Key Validation**: Test external API connectivity (if keys provided)

### Configuration Audit

```bash
# Check configuration via API
curl -X GET http://localhost:5000/api/system/config \
  -H "Authorization: Bearer <admin-token>"
```

Response includes:
- Environment validation status
- API key configuration status (without exposing keys)
- Database connection status
- MCP server availability
- Security configuration compliance

---

## Troubleshooting Configuration Issues

### Common Configuration Problems

#### **Database Connection Issues**
```bash
# Check connection
kubectl exec -it deployment/osint-backend -n osint-platform -- \
  python -c "
import os
import psycopg2
try:
    conn = psycopg2.connect(os.environ['POSTGRES_URL'])
    print('Database connection successful')
except Exception as e:
    print(f'Database connection failed: {e}')
"
```

#### **MCP Server Connectivity**
```bash
# Test MCP connectivity
kubectl exec -it deployment/osint-backend -n osint-platform -- \
  curl -s http://mcp-infrastructure-enhanced:8021/health
```

#### **API Key Validation**
```bash
# Check API key configuration
kubectl exec -it deployment/osint-backend -n osint-platform -- \
  python -c "
import os
keys = ['VIRUSTOTAL_API_KEY', 'OPENAI_API_KEY', 'SHODAN_API_KEY']
for key in keys:
    value = os.environ.get(key, 'Not configured')
    status = 'Configured' if value != 'Not configured' else 'Missing'
    print(f'{key}: {status}')
"
```

### Debug Commands

```bash
# View environment variables
kubectl exec -it deployment/osint-backend -n osint-platform -- env | grep -E "(POSTGRES|JWT|MCP)"

# Check secret contents
kubectl get secret osint-api-keys -n osint-platform -o yaml

# Verify service discovery
kubectl exec -it deployment/osint-backend -n osint-platform -- nslookup mcp-infrastructure-enhanced
```

For additional troubleshooting, see the [Deployment Guide](DEPLOYMENT_GUIDE.md) and [Architecture Overview](ARCHITECTURE_OVERVIEW.md).