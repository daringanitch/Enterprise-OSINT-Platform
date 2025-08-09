# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

**Enterprise OSINT Platform - Flask + React Edition** - A professional-grade Open Source Intelligence investigation platform built with Flask backend and React frontend. Features multi-agent OSINT capabilities, real-time processing, enterprise compliance (GDPR/CCPA/PIPEDA), and production-ready Kubernetes deployment.

### Core Architecture Components

### 1. Backend Services (`backend/`)
Flask-based REST API with modular structure:
- **API Layer** (`api/`) - RESTful endpoints for auth, investigations, reports, MCP integration
- **Models** (`models/`) - SQLAlchemy ORM for PostgreSQL (users, investigations, reports)
- **Services** (`services/`) - Business logic (OSINT processing, MCP clients, PDF generation)
- **Tasks** (`tasks/`) - Celery background tasks for async processing
- **Utils** - Common utilities and helpers

### 2. Frontend Application (`frontend/`)
React 18+ TypeScript SPA with Material-UI:
- **Components** - Reusable UI components
- **Pages** - Route-specific page components
- **Services** - API clients and data fetching
- **Store** - Redux Toolkit state management
- **Types** - TypeScript type definitions

### 3. MCP (Model Context Protocol) Servers (`mcp-servers/`)
Specialized OSINT collection microservices:
- **Infrastructure MCP** - DNS, WHOIS, certificate analysis
- **Social Media MCP** - Twitter, LinkedIn, Reddit intelligence
- **Threat Intel MCP** - VirusTotal, threat feeds, malware analysis

### 4. Simple Architecture Alternative (`simple-backend/`, `simple-frontend/`)
Lightweight deployment option with minimal dependencies for demos/testing

### 5. Deployment Infrastructure
- **Docker** containers with multi-stage builds
- **Kubernetes** manifests with Helm charts
- **PostgreSQL** audit database with optimized schema
- **HashiCorp Vault** for secrets management

## Development Commands

### Prerequisites
- **Backend**: Python 3.9+
- **Frontend**: Node.js 18+, npm/yarn
- **Container**: Docker for image builds
- **Orchestration**: Kubernetes cluster (required - local or cloud)

### Backend Development
```bash
# Environment setup
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Database setup (requires PostgreSQL running)
export POSTGRES_URL="postgresql://postgres:password@localhost:5432/osint_audit"
flask db upgrade

# Run development server
flask run  # http://localhost:5000

# Background tasks (separate terminal)
celery -A app.celery worker --loglevel=info
```

### Frontend Development
```bash
cd frontend
npm install

# Development server
npm start  # http://localhost:3000

# Build production assets
npm run build

# Code quality
npm run lint
npm run format
```

### Testing & Code Quality
```bash
# Backend testing
cd backend
source venv/bin/activate
pytest  # Run test suite
black .  # Format code
flake8 .  # Lint code
mypy .   # Type checking

# Frontend testing  
cd frontend
npm test
npm run lint
npm run lint:fix
```

### Kubernetes Development
```bash
# Local development cluster setup
make setup  # Initialize local K8s environment

# Deploy to local Kubernetes
make deploy  # Full cluster deployment
kubectl get pods -n osint-platform

# View logs and status
kubectl logs -f deployment/backend -n osint-platform
make status  # System health check via API
```

### Production Deployment
```bash
# Production Kubernetes deployment
make deploy  # Full cluster deployment to current kubectl context
kubectl get pods -n osint-platform

# Helm deployment (recommended for production)
cd helm/osint-platform
helm install osint-platform . -n osint-platform --create-namespace -f values-production.yaml

# Local access via port forwarding
make port-forward
kubectl port-forward -n osint-platform svc/osint-backend 5000:5000
kubectl port-forward -n osint-platform svc/osint-frontend 8080:80
```

## Architecture Patterns

### Multi-Agent Investigation System
The platform orchestrates specialized agents for different OSINT domains:
- **Investigation Orchestrator** manages concurrent investigations
- **MCP Clients** interface with specialized collection servers
- **Compliance Framework** ensures regulatory adherence
- **Risk Assessment Engine** calculates threat scores and confidence levels
- **Professional Report Generator** creates executive and technical reports

### Database Schema (PostgreSQL)
Audit-focused schema with 7 core tables in `osint_audit` database:
- `audit.events` - System audit trail
- `audit.investigations` - Investigation lifecycle tracking  
- `audit.api_key_usage` - API consumption and cost tracking
- `audit.risk_assessments` - Risk scoring and threat analysis
- `audit.compliance_assessments` - Regulatory compliance status
- `audit.system_metrics` - Performance and operational data
- `audit.configuration_changes` - Configuration audit trail

### Security Architecture
- **Authentication**: JWT tokens with refresh mechanism
- **Authorization**: Role-based access control (RBAC)
- **Secrets**: HashiCorp Vault integration
- **Network**: TLS 1.3, mTLS for service communication
- **Compliance**: GDPR/CCPA/PIPEDA assessment engines

## Key Configuration Files

- `backend/requirements.txt` - Python dependencies (Flask, SQLAlchemy, Celery, etc.)
- `frontend/package.json` - Node.js dependencies (React, TypeScript, Material-UI)
- `k8s/` - Kubernetes deployment manifests (base configuration)
- `k8s/overlays/production/` - Production-specific Kubernetes configs
- `helm/osint-platform/` - Helm chart for production deployment
- `Makefile` - Common development and deployment operations

## API Endpoints

### Core REST API (`/api/`)
- `POST /api/auth/login` - User authentication
- `GET|POST /api/investigations` - Investigation CRUD operations  
- `GET /api/investigations/{id}/report` - Generate investigation reports
- `GET /api/mcp/servers` - MCP server status and capabilities
- `POST /api/mcp/execute` - Execute OSINT collection tools

### Real-time Features
- **WebSocket** support for live investigation progress updates
- **Background processing** via Celery for long-running OSINT tasks
- **Real-time dashboards** with investigation metrics and system status

## Environment Variables

### Required for Production
```bash
# Database
POSTGRES_URL="postgresql://user:pass@host:5432/osint_audit"

# Security
JWT_SECRET_KEY="your-secret-key"
VAULT_ADDR="http://vault:8200"
VAULT_TOKEN="vault-token"

# External APIs (stored in Vault)
OPENAI_API_KEY="your-openai-key"
TWITTER_BEARER_TOKEN="your-twitter-token"
SHODAN_API_KEY="your-shodan-key"
VIRUSTOTAL_API_KEY="your-vt-key"

# Services
REDIS_URL="redis://localhost:6379"
CELERY_BROKER_URL="redis://localhost:6379"
```

## Development Workflows

### Starting New Investigation Feature
1. Create database migration for new tables/columns
2. Add SQLAlchemy models in `backend/app/models/`
3. Implement API endpoints in `backend/app/api/`
4. Add Celery background tasks if needed
5. Create React components and pages
6. Add Redux state management
7. Write tests for both backend and frontend

### Adding New MCP Server
1. Create new directory in `mcp-servers/`
2. Implement MCP protocol server with OSINT tools
3. Add Docker container configuration
4. Update Kubernetes manifests for deployment
5. Register server in MCP client configuration

### Compliance Framework Extension
1. Add new regulatory framework in `compliance_framework.py`
2. Implement assessment logic and scoring
3. Update database schema for new compliance data
4. Add reporting templates and export formats

## Production Considerations

### Kubernetes-Native Features
- **Horizontal Pod Autoscaling** for backend and worker pods
- **Persistent Volume Claims** for PostgreSQL and Vault data
- **Network Policies** for micro-segmentation
- **RBAC** for service account permissions
- **Ingress Controllers** for external access and SSL termination

### Database Performance
- Connection pooling configured for high concurrency
- Optimized indexes on audit tables for query performance  
- Automated backup via Kubernetes CronJobs
- Query performance monitoring with Prometheus metrics

### Scalability
- Kubernetes HPA for automatic scaling based on CPU/memory
- Redis caching for frequently accessed data
- Celery worker scaling via Kubernetes deployments
- Multi-zone deployment for high availability

### Security Hardening
- Container images scanned with admission controllers
- Pod security policies and security contexts
- Network policies for pod-to-pod communication
- Vault operator for automated secrets management
- Comprehensive audit logging to centralized systems