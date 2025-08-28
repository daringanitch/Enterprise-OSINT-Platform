# Enterprise OSINT Platform

A production-ready Open Source Intelligence (OSINT) investigation platform built with modern web technologies and Kubernetes-native architecture. Designed for enterprise security teams, threat hunters, and intelligence analysts.

## 🚀 Platform Overview

The Enterprise OSINT Platform provides comprehensive intelligence gathering capabilities through specialized MCP (Model Context Protocol) servers, with professional reporting and enterprise compliance features.

### **Current Production Architecture**

```
┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────────┐
│   React Frontend    │────▶│   Flask Backend     │────▶│    Enhanced MCP Servers │
│   (JavaScript +     │     │   (REST API +       │     │   (FastAPI + uvicorn)   │
│    Material-UI)     │     │    SQLAlchemy)      │     │                         │
└─────────────────────┘     └─────────────────────┘     └─────────────────────────┘
                                      │                              │
                                      ▼                              ▼
                            ┌─────────────────────┐     ┌─────────────────────────┐
                            │    PostgreSQL       │     │    External APIs        │
                            │  (Audit Database)   │     │  (VirusTotal, Shodan,   │
                            └─────────────────────┘     │   Twitter, OpenAI, etc) │
                                                        └─────────────────────────┘
```

## 🛠️ Technology Stack

### **Backend Services**
- **Flask 2.3+** - REST API framework with JWT authentication
- **SQLAlchemy 2.0** - PostgreSQL ORM for audit and investigation data
- **aiohttp + asyncio** - Asynchronous HTTP client for MCP communication
- **Professional Reporting** - PDF generation with executive summaries

### **Frontend Application**
- **React 18** - Modern component-based UI
- **Material-UI v5** - Professional component library
- **Axios** - HTTP client for API communication
- **jsPDF** - Client-side PDF generation

### **Enhanced MCP Servers (FastAPI)**
- **Infrastructure Advanced** (Port 8021) - DNS, WHOIS, SSL, Certificate Transparency
- **Threat Intelligence Aggregator** (Port 8020) - Multi-source threat feeds
- **AI-Powered Analyzer** (Port 8050) - GPT-4 enhanced analysis
- **Social Media Enhanced** (Port 8010) - Social intelligence gathering
- **Financial Intelligence** (Port 8040) - SEC filings, financial analysis

### **Infrastructure**
- **Kubernetes 1.28+** - Container orchestration
- **PostgreSQL 15** - Primary database with audit schema
- **Redis 7** - Session management and caching
- **Prometheus** - Metrics collection and monitoring
- **Grafana** - Visualization and dashboards
- **HashiCorp Vault** - Secrets management (multiple deployment options)
- **Docker** - Container runtime

## 📁 Current Project Structure

```
enterprise-osint-flask/
├── simple-backend/                    # Flask REST API
│   ├── app.py                        # Main application
│   ├── models.py                     # Database models
│   ├── investigation_orchestrator.py # Investigation engine
│   ├── mcp_clients.py               # MCP communication
│   ├── professional_report_generator.py
│   └── requirements.txt
│
├── simple-frontend/                  # React SPA
│   ├── index.html                   # Main entry point
│   ├── js/app.js                    # React application
│   ├── css/styles.css               # Material-UI styling
│   └── package.json
│
├── mcp-servers/                     # Enhanced MCP Servers
│   ├── infrastructure-advanced/     # FastAPI server (8021)
│   ├── threat-aggregator/          # FastAPI server (8020)
│   ├── ai-analyzer/               # FastAPI server (8050)
│   ├── social-media-enhanced/     # Flask server (8010)
│   └── financial-enhanced/        # Flask server (8040)
│
├── k8s/                            # Kubernetes manifests
│   ├── enhanced-mcp-deployments.yaml
│   ├── simple-backend-deployment.yaml
│   ├── simple-frontend-deployment.yaml
│   └── postgresql-deployment.yaml
│
└── docs/                           # Documentation
    ├── README.md
    ├── ARCHITECTURE_OVERVIEW.md
    ├── API_REFERENCE.md
    └── DEPLOYMENT_GUIDE.md
```

## 🔧 **Local Development Setup**

### **Prerequisites**
- Docker Desktop with Kubernetes enabled
- Python 3.11+
- Node.js 18+
- kubectl configured for local cluster

### **1. Deploy to Kubernetes**
```bash
# Create namespace and deploy all services
kubectl create namespace osint-platform

# Deploy PostgreSQL
kubectl apply -f k8s/postgresql-deployment.yaml

# Deploy backend services
kubectl apply -f k8s/simple-backend-deployment.yaml

# Deploy frontend
kubectl apply -f k8s/simple-frontend-deployment.yaml

# Deploy enhanced MCP servers
kubectl apply -f k8s/enhanced-mcp-deployments.yaml
kubectl apply -f k8s/mcp-*-enhanced-deployment.yaml
```

### **2. Access the Platform**
```bash
# Port forward services for local access
kubectl port-forward -n osint-platform svc/osint-simple-frontend 8080:80
kubectl port-forward -n osint-platform svc/osint-backend 5000:5000

# Access the application
# Frontend: http://localhost:8080
# Backend API: http://localhost:5000
```

### **3. Configuration**
```bash
# Create API keys secret (optional - servers work without keys)
kubectl create secret generic osint-api-keys \
  --namespace=osint-platform \
  --from-literal=openai-api-key=your-key \
  --from-literal=virustotal-api-key=your-key \
  --from-literal=shodan-api-key=your-key
```

## 🔍 **Core Features**

### **Intelligence Gathering**
- **Infrastructure Analysis**: WHOIS, DNS records, SSL certificates, subdomains
- **Threat Intelligence**: Multi-source reputation checking (VirusTotal, Shodan, AbuseIPDB)
- **Social Media Intelligence**: Profile analysis across platforms
- **AI-Enhanced Analysis**: GPT-4 powered threat assessment and reporting
- **Financial Intelligence**: SEC filings, company research

### **Investigation Management**
- **Multi-Stage Workflow**: Planning → Collection → Analysis → Reporting
- **Real-time Progress Tracking**: Live updates during investigation
- **Professional Reporting**: Executive and technical PDF reports
- **Audit Trail**: Complete investigation history in PostgreSQL

### **Enterprise Features**
- **JWT Authentication**: Secure user management
- **Role-Based Access**: Admin, analyst, and viewer roles
- **Compliance Framework**: GDPR/CCPA assessment integration
- **API Rate Limiting**: Protection against abuse
- **Comprehensive Logging**: Full audit trail

## 🔐 **API Endpoints**

### **Authentication**
```
POST /api/auth/login     # User login
POST /api/auth/logout    # User logout
```

### **Investigations**
```
GET  /api/investigations              # List investigations
POST /api/investigations              # Start new investigation
GET  /api/investigations/{id}         # Get investigation details
GET  /api/investigations/{id}/report  # Generate PDF report
```

### **System**
```
GET /api/system/status    # Platform health check
GET /api/mcp/servers      # MCP server status
```

## 🏃‍♂️ **Quick Start Example**

### **1. Login**
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

### **2. Start Investigation**
```bash
curl -X POST http://localhost:5000/api/investigations \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "investigation_type": "comprehensive"
  }'
```

### **3. Check Results**
```bash
curl -X GET http://localhost:5000/api/investigations/{id} \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 📊 **Enhanced MCP Server Capabilities**

### **Infrastructure Advanced (Port 8021)**
- Certificate Transparency log searches
- Passive DNS resolution history
- ASN (Autonomous System) lookups
- Reverse IP domain discovery
- Common port scanning
- Web technology detection
- Subdomain takeover checks

### **Threat Aggregator (Port 8020)**
- Multi-source IP reputation (VirusTotal, AbuseIPDB, Shodan, OTX)
- Domain reputation analysis
- File hash checking
- Threat hunting across indicators
- Real-time threat scoring

### **AI Analyzer (Port 8050)**
- GPT-4 powered threat actor profiling
- Indicator correlation and pattern detection
- Executive summary generation
- Attack vector prediction
- MITRE ATT&CK framework mapping
- Intelligence gap identification

## 🚀 **Production Deployment**

The platform is designed for production Kubernetes deployment. Key features:

- **High Availability**: Multi-replica deployments
- **Auto-scaling**: Horizontal Pod Autoscaling
- **Security**: Network policies, RBAC, secrets management
- **Monitoring**: Prometheus metrics and Grafana dashboards
- **Persistence**: PostgreSQL with persistent volumes

See `DEPLOYMENT_GUIDE.md` for detailed production setup.

## 📊 **Monitoring & Observability**

### **Prometheus Metrics Stack**
The platform includes comprehensive monitoring with:
- **Service Discovery**: Automatic discovery of Kubernetes pods
- **Custom Metrics**: OSINT-specific metrics for investigations, API usage, and MCP server health
- **Pre-configured Alerts**: Investigation failures, API errors, resource utilization
- **Retention**: 15-day metric retention with efficient storage

### **Grafana Dashboards**
Pre-built dashboards for:
- **Platform Overview**: Investigation metrics, API performance, system health
- **MCP Server Status**: Individual server health, response times, error rates
- **Resource Utilization**: CPU, memory, network, storage metrics
- **Investigation Analytics**: Success rates, processing times, API usage patterns

### **Health Monitoring**
- **Automated Health Checks**: CronJob running every 5 minutes
- **Endpoint Monitoring**: Backend API, system status, MCP servers, investigations
- **Custom Metrics Exporter**: Converts health status to Prometheus metrics
- **Alert Integration**: Failed health checks trigger alerts

## 🔧 **Configuration**

### **Required Environment Variables**
```bash
# Database
POSTGRES_URL=postgresql://postgres:password@postgresql:5432/osint_audit

# Security
JWT_SECRET_KEY=your-secure-secret-key

# MCP Server URLs (internal Kubernetes)
MCP_INFRASTRUCTURE_URL=http://mcp-infrastructure-enhanced:8021
MCP_THREAT_URL=http://mcp-threat-enhanced:8020
MCP_AI_URL=http://mcp-technical-enhanced:8050
```

### **Optional API Keys**
```bash
# External integrations (store in Kubernetes secrets)
OPENAI_API_KEY=your-openai-key
VIRUSTOTAL_API_KEY=your-virustotal-key
SHODAN_API_KEY=your-shodan-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
```

## 📈 **System Status**

Current deployment includes:

### **Core Services**
- ✅ Backend API (2 replicas) - Flask REST API with JWT auth
- ✅ React Frontend (2 replicas) - Material-UI SPA
- ✅ PostgreSQL Database (1 replica) - Audit and investigation storage
- ✅ Redis Cache (3 replicas) - Session management

### **MCP Intelligence Servers**
- ✅ Infrastructure MCP (2 replicas) - Port 8021
- ✅ Threat MCP (1 replica) - Port 8020
- ✅ AI Analyzer MCP (1 replica) - Port 8050
- ✅ Social Media MCP (1 replica) - Port 8010
- ✅ Financial MCP (1 replica) - Port 8040

### **Monitoring Stack**
- ✅ Prometheus Server - Metrics collection
- ✅ Grafana - Dashboards and visualization
- ✅ Health Monitor - Automated health checks (5-minute intervals)
- ✅ Metrics Exporter - Custom OSINT metrics
- ✅ Vault - Secret management (dev mode)

## 📚 **Documentation**

- [Architecture Overview](ARCHITECTURE_OVERVIEW.md) - Detailed system architecture
- [API Reference](API_REFERENCE.md) - Complete API documentation
- [Deployment Guide](DEPLOYMENT_GUIDE.md) - Production deployment instructions
- [Configuration Reference](CONFIGURATION.md) - Environment and API setup

## 🤝 **Contributing**

1. Fork the repository
2. Create feature branch: `git checkout -b feature/new-capability`
3. Commit changes: `git commit -m 'Add new OSINT capability'`
4. Push to branch: `git push origin feature/new-capability`
5. Submit pull request

## 📄 **License**

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Enterprise OSINT Platform** - Professional open-source intelligence gathering for modern security teams.