# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

**Enterprise OSINT Platform** - A production-ready Open Source Intelligence investigation platform built with Flask backend, React frontend, and FastAPI-based MCP servers. Features enhanced intelligence gathering capabilities, AI-powered analysis, enterprise compliance, and Kubernetes-native deployment.

### Core Architecture Components

### 1. Backend Service (`simple-backend/`)
Flask-based REST API with integrated features:
- **Main Application** (`app.py`) - Flask REST API with JWT authentication
- **Models** (`models.py`) - SQLAlchemy ORM for PostgreSQL audit database
- **Investigation Engine** (`investigation_orchestrator.py`) - Multi-stage investigation workflow
- **MCP Communication** (`mcp_clients.py`) - HTTP client for MCP server integration
- **Reporting** (`professional_report_generator.py`) - PDF report generation
- **Compliance** (`compliance_framework.py`) - GDPR/CCPA/PIPEDA validation

### 2. Frontend Application (`simple-frontend/`)
React 18 SPA with modern JavaScript:
- **Main Application** (`js/app.js`) - React components and state management
- **API Client** (`js/api.js`) - Axios-based backend communication
- **Components** (`js/components.js`) - Reusable UI components
- **Styling** (`css/styles.css`) - Material-UI integration

### 3. Enhanced MCP Servers (`mcp-servers/`)
FastAPI-based specialized intelligence services:
- **Infrastructure Advanced** (`infrastructure-advanced/`) - FastAPI server on port 8021
  - Certificate Transparency, DNS analysis, ASN lookup, port scanning
- **Threat Aggregator** (`threat-aggregator/`) - FastAPI server on port 8020
  - Multi-source threat intelligence (VirusTotal, Shodan, AbuseIPDB, OTX)
- **AI Analyzer** (`ai-analyzer/`) - FastAPI server on port 8050
  - GPT-4 powered analysis, threat profiling, executive summaries
- **Social Media Enhanced** (`social-media-enhanced/`) - Flask server on port 8010
  - Social intelligence gathering across platforms
- **Financial Enhanced** (`financial-enhanced/`) - Flask server on port 8040
  - Financial intelligence and SEC analysis

### 4. Deployment Infrastructure
- **Kubernetes** manifests with production-ready configurations
- **PostgreSQL** 15 with audit schema and persistent storage
- **Redis** cluster for session management and caching
- **Docker** containers with security hardening

## Development Commands

### Prerequisites
- **Backend**: Python 3.11+
- **Frontend**: Node.js 18+, npm
- **Container**: Docker Desktop with Kubernetes enabled
- **Tools**: kubectl, helm (optional)

### Kubernetes Development with Demo/Production Mode (Recommended)
```bash
# Quick deployment with automated script
./deploy-demo-production-mode.sh

# Manual deployment steps
kubectl create namespace osint-platform

# Deploy mode configuration and API key templates
kubectl apply -f k8s/mode-config-configmap.yaml
kubectl apply -f k8s/api-keys-secret-template.yaml

# Deploy core services
kubectl apply -f k8s/postgresql-deployment.yaml
kubectl apply -f k8s/simple-backend-deployment.yaml    # Includes mode management
kubectl apply -f k8s/simple-frontend-deployment.yaml  # Includes mode toggle UI

# Deploy enhanced MCP servers (optional)
kubectl apply -f k8s/enhanced-mcp-deployments.yaml
kubectl apply -f k8s/mcp-threat-enhanced-deployment.yaml
kubectl apply -f k8s/mcp-technical-enhanced-deployment.yaml

# Access via port forwarding (handled by script)
kubectl port-forward -n osint-platform svc/osint-simple-frontend 8080:80
kubectl port-forward -n osint-platform svc/osint-backend 5000:5000

# Frontend with Mode Toggle: http://localhost:8080
# Backend API with Mode Management: http://localhost:5000
```

### Adding Production API Keys
```bash
# Create production API keys secret
kubectl create secret generic osint-api-keys \
  --from-literal=OPENAI_API_KEY='your-openai-key' \
  --from-literal=VIRUSTOTAL_API_KEY='your-virustotal-key' \
  --from-literal=SHODAN_API_KEY='your-shodan-key' \
  --from-literal=ABUSEIPDB_API_KEY='your-abuseipdb-key' \
  --from-literal=TWITTER_API_KEY='your-twitter-key' \
  --from-literal=REDDIT_API_KEY='your-reddit-key' \
  -n osint-platform

# Restart backend to pick up keys
kubectl rollout restart deployment/osint-backend -n osint-platform

# Switch to production mode via UI toggle or API
curl -X POST http://localhost:5000/api/system/mode \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"mode": "production"}'
```

### Local Development (Alternative)
```bash
# Backend development
cd simple-backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Set environment variables
export POSTGRES_URL="postgresql://postgres:password@localhost:5432/osint_audit"
export JWT_SECRET_KEY="dev-secret-key"

# Run Flask development server
python app.py  # http://localhost:5000

# Frontend development
cd simple-frontend
npm install
npm start  # http://localhost:3000 (if using dev server)
```

### MCP Server Development
```bash
# Infrastructure Advanced MCP
cd mcp-servers/infrastructure-advanced
pip install -r requirements.txt
python app.py  # FastAPI server on port 8021

# Threat Aggregator MCP
cd mcp-servers/threat-aggregator
pip install -r requirements.txt
python app.py  # FastAPI server on port 8020

# AI Analyzer MCP
cd mcp-servers/ai-analyzer
pip install -r requirements.txt
export OPENAI_API_KEY="your-key"  # Optional
python app.py  # FastAPI server on port 8050
```

### Testing & Quality
```bash
# Backend testing
cd simple-backend
python -m pytest tests/  # Run test suite
python -c "import app; print('App imports successfully')"

# Test API endpoints
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Test MCP server connectivity
curl -s http://localhost:8021/health  # Infrastructure MCP
curl -s http://localhost:8020/health  # Threat MCP
curl -s http://localhost:8050/health  # AI MCP
```

## Architecture Patterns

### Multi-Agent Investigation System
The platform orchestrates specialized agents for different OSINT domains:
- **Investigation Orchestrator** manages concurrent investigations with 7-stage workflow
- **MCP Clients** interface with specialized FastAPI/Flask collection servers
- **Compliance Framework** ensures GDPR/CCPA/PIPEDA adherence
- **Risk Assessment Engine** calculates threat scores and confidence levels
- **Professional Report Generator** creates PDF reports with executive summaries

### Database Schema (PostgreSQL)
Audit-focused schema with core tables in `osint_audit` database:
- `audit.events` - System audit trail with compliance tracking
- `audit.investigations` - Investigation lifecycle and results
- `audit.api_key_usage` - External API consumption monitoring
- `audit.risk_assessments` - Threat scoring and risk analysis
- `audit.compliance_assessments` - Regulatory compliance validation
- `audit.system_metrics` - Performance and operational metrics

### Security Architecture
- **Authentication**: JWT tokens with configurable expiration
- **Authorization**: Role-based access control (admin/analyst/viewer)
- **Network Security**: Kubernetes network policies for pod-to-pod communication
- **Secrets Management**: Kubernetes secrets for API keys and credentials
- **Audit Logging**: Complete investigation and system audit trail

## Key Configuration Files

- `simple-backend/requirements.txt` - Python dependencies (Flask, SQLAlchemy, aiohttp)
- `simple-frontend/package.json` - Node.js dependencies (React, Material-UI, Axios)
- `k8s/` - Kubernetes deployment manifests (base configuration)
- `mcp-servers/*/requirements.txt` - MCP server dependencies (FastAPI, uvicorn, domain-specific libraries)
- `CONFIGURATION.md` - Complete environment and API configuration guide
- `DEPLOYMENT_GUIDE.md` - Production deployment instructions

## API Endpoints

### Core REST API (`simple-backend/app.py`)
- `POST /api/auth/login` - JWT authentication with admin/admin123
- `POST /api/auth/logout` - Session termination
- `GET|POST /api/investigations` - Investigation CRUD operations
- `GET /api/investigations/{id}` - Investigation details and results
- `GET /api/investigations/{id}/report` - Generate professional PDF reports
- `GET /api/system/status` - Platform health and component status
- `GET /api/mcp/servers` - MCP server status and capabilities

### Enhanced MCP Server APIs
- **Infrastructure Advanced (8021)**: `/capabilities`, `/infrastructure/*` endpoints
- **Threat Aggregator (8020)**: `/capabilities`, `/threat/*` endpoints  
- **AI Analyzer (8050)**: `/capabilities`, `/ai/*` endpoints
- **Social Enhanced (8010)**: Social media intelligence endpoints
- **Financial Enhanced (8040)**: Financial intelligence endpoints

## Environment Variables

### Required for Production
```bash
# Database
POSTGRES_URL="postgresql://user:pass@host:5432/osint_audit"

# Security  
JWT_SECRET_KEY="your-secure-secret-key"

# MCP Server URLs (internal Kubernetes)
MCP_INFRASTRUCTURE_URL="http://mcp-infrastructure-enhanced:8021"
MCP_THREAT_URL="http://mcp-threat-enhanced:8020"
MCP_AI_URL="http://mcp-technical-enhanced:8050"
```

### Optional API Keys (stored in Kubernetes secrets)
```bash
# External integrations
OPENAI_API_KEY="your-openai-key"           # For AI-powered analysis
VIRUSTOTAL_API_KEY="your-virustotal-key"   # Threat intelligence
SHODAN_API_KEY="your-shodan-key"           # Network intelligence
ABUSEIPDB_API_KEY="your-abuseipdb-key"     # IP reputation
```

## Development Workflows

### Starting New Investigation Feature
1. Add endpoint to `simple-backend/app.py`
2. Update investigation orchestrator in `investigation_orchestrator.py`
3. Modify MCP client communication in `mcp_clients.py`
4. Add frontend components in `simple-frontend/js/app.js`
5. Test end-to-end workflow with investigation creation

### Adding New MCP Server
1. Create new directory in `mcp-servers/`
2. Implement FastAPI server with `/health`, `/capabilities`, domain-specific endpoints
3. Add Dockerfile and requirements.txt
4. Create Kubernetes deployment manifest
5. Update MCP client configuration in backend

### Enhancing Intelligence Capabilities
1. Add new tools to existing MCP servers or create new specialized server
2. Update MCP server capabilities endpoint
3. Integrate new intelligence sources in investigation orchestrator
4. Add results processing in professional report generator

## Production Considerations

### Kubernetes-Native Features
- **Multi-replica deployments** for high availability
- **Persistent Volume Claims** for PostgreSQL data persistence
- **Secrets management** for API keys and database credentials
- **Network Policies** for micro-segmentation between services
- **Health checks** for all services with automatic restart
- **Resource limits** and requests for optimal scheduling

### Database Performance
- **Connection pooling** configured for concurrent investigations
- **Optimized indexes** on investigation and audit tables
- **Audit retention** policies for compliance requirements
- **Backup strategies** with PostgreSQL automated snapshots

### Security Hardening
- **Pod Security Standards** with restricted policies
- **RBAC** for service account permissions and least privilege
- **Network policies** for pod-to-pod communication restrictions
- **TLS termination** at ingress with certificate management
- **Container security** with non-root users and read-only filesystems

## Demo/Production Mode System

### Mode Management
The platform includes a sophisticated demo/production mode system that allows seamless switching between demonstration data and live API integrations.

**Key Features:**
- **UI Toggle Switch** - Easy mode switching directly from the web interface
- **Automatic Fallback** - Auto-switches to demo mode if required API keys are missing
- **API Key Validation** - Real-time validation and status display of external API keys
- **Kubernetes-Native** - Full configuration management via ConfigMaps and Secrets

### Mode Comparison

| Feature | Demo Mode | Production Mode |
|---------|-----------|-----------------|
| **Data Source** | Synthetic/Mock Data | Live API Integrations |
| **API Keys** | Not Required | Optional/Required |
| **Investigations** | 5 Sample Cases | Real-time Analysis |
| **Threat Intel** | Simulated Results | VirusTotal, Shodan, etc. |
| **Social Analysis** | Mock Profiles | Twitter, Reddit APIs |
| **AI Analysis** | Templated Reports | OpenAI GPT Integration |
| **Cost** | Free | API Usage Costs |
| **Safety** | No External Calls | Real External Requests |

### API Endpoints for Mode Management
- `GET /api/system/mode` - Current mode status and API key availability
- `POST /api/system/mode` - Switch between demo/production modes
- `GET /api/system/api-keys` - API key status and descriptions
- `GET /api/system/demo-data` - Demo data configuration

### Demo Data Features
- **5 Realistic Sample Investigations** with varied targets and findings
- **Multi-category Intelligence** covering infrastructure, threat, and social domains
- **Synthetic Risk Scores** with realistic confidence levels
- **Mock API Responses** simulating real-world OSINT data patterns
- **Comprehensive Reports** with executive summaries and technical details

### Production Mode Requirements
**Optional API Keys** (platform works without any keys in demo mode):
- `OPENAI_API_KEY` - Advanced AI analysis and report generation
- `VIRUSTOTAL_API_KEY` - Malware and reputation scanning
- `SHODAN_API_KEY` - Network and infrastructure intelligence
- `ABUSEIPDB_API_KEY` - IP reputation and abuse reporting
- `TWITTER_API_KEY` - Social media intelligence gathering
- `REDDIT_API_KEY` - Social media analysis and monitoring

### Kubernetes Configuration Files
- `k8s/mode-config-configmap.yaml` - Default mode configuration
- `k8s/api-keys-secret-template.yaml` - API key secret template
- `simple-backend/mode_manager.py` - Python mode management system
- `simple-backend/demo_data.py` - Demo data provider

## Current System Status

### Active Services (as of current deployment)
- ✅ Backend API with Mode System (2 replicas) - Flask REST API with demo/production switching
- ✅ Frontend with Mode Toggle (2 replicas) - Enhanced SPA with mode toggle UI
- ✅ PostgreSQL Database (1 replica) - Audit and investigation storage
- ✅ Redis Cache (3 replicas) - Session and caching
- ✅ Infrastructure MCP (2 replicas) - FastAPI advanced infrastructure intelligence
- ✅ Threat MCP (1 replica) - FastAPI multi-source threat aggregation
- ✅ AI Analyzer MCP (1 replica) - FastAPI GPT-4 powered analysis
- ✅ Social Media MCP (1 replica) - Social intelligence gathering
- ✅ Financial MCP (1 replica) - Financial intelligence analysis

### Enhanced Platform Capabilities
- **Demo/Production Mode Switching** - Seamless toggling between synthetic and live data
- **Multi-stage investigations** with real-time progress tracking
- **Professional PDF reporting** with executive summaries
- **Enterprise compliance** validation (GDPR/CCPA/PIPEDA)
- **AI-enhanced analysis** with threat actor profiling
- **Multi-source threat intelligence** aggregation
- **Infrastructure analysis** with certificate transparency
- **Social media intelligence** across platforms
- **Financial intelligence** with SEC integration
- **Automatic API Key Validation** with fallback to demo mode
- **Kubernetes-Native Configuration** with ConfigMaps and Secrets management



## Current Repository State

**Last Updated**: 2025-08-25 15:04:16
**Branch**: main
**Latest Commit**: 420fdf9

### Recent Commits

- 420fdf9: Add monitoring infrastructure and production deployment improvements (18 hours ago)
- 2fdfe55: Fix Vault deployment with simplified development configuration (7 days ago)
- 144676d: Fix frontend API URL configuration (7 days ago)
- 41b815a: Complete DR Roadmap & Updated Helm Chart v2.0 (9 days ago)
- 77ab103: Major Documentation & Architecture Updates (9 days ago)
- d79f4e2: Major Platform Enhancement: 1-Hour Report Lifecycle + Persistent Audit History + Production Features (13 days ago)
- a41fed4: Fix login UX: eliminate failed login cycling issue (2 weeks ago)
- 97a058b: Update Docker images and deployment configs to v1.0.0-auth (2 weeks ago)
- 949eeea: Add complete JWT authentication system with email verification (2 weeks ago)
- d042d91: Initial commit: Enterprise OSINT Platform with Kubernetes-native architecture (2 weeks ago)
