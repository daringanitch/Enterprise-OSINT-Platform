# Enterprise OSINT Platform - Comprehensive Architecture Overview

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [System Architecture](#system-architecture)
3. [Core Components](#core-components)
4. [Technology Stack](#technology-stack)
5. [Data Flow and Workflows](#data-flow-and-workflows)
6. [Security Architecture](#security-architecture)
7. [Deployment Architecture](#deployment-architecture)
8. [API Documentation](#api-documentation)
9. [Configuration Guide](#configuration-guide)
10. [Code Structure](#code-structure)

---

## Executive Summary

The Enterprise OSINT Platform is a Kubernetes-native, microservices-based open-source intelligence gathering system designed for enterprise security teams, threat hunters, and intelligence analysts. It features:

- **Multi-Agent Intelligence Collection**: Specialized MCP (Model Context Protocol) servers for different intelligence domains
- **Real-Time Processing**: Asynchronous investigation workflow with progress tracking
- **Enterprise Compliance**: Built-in GDPR/CCPA/PIPEDA compliance frameworks
- **Professional Reporting**: PDF generation with executive summaries and risk assessments
- **Scalable Architecture**: Kubernetes-based deployment with horizontal scaling capabilities

### Key Capabilities
- **Infrastructure Intelligence**: WHOIS, DNS, SSL certificate analysis, subdomain enumeration
- **Social Media Intelligence**: Twitter/X, Reddit, LinkedIn analysis with sentiment tracking
- **Threat Intelligence**: VirusTotal integration, Shodan scanning, threat feed correlation
- **Financial Intelligence**: SEC filings, stock data, company analysis
- **Technical Intelligence**: GitHub/GitLab repository analysis, code intelligence

---

## System Architecture

### High-Level Architecture

```
┌─────────────────────┐
│   Web Interface     │
│  (React + TypeScript)│
└──────────┬──────────┘
           │ HTTPS/REST
           ▼
┌─────────────────────┐     ┌─────────────────────┐
│   Backend API       │────▶│   PostgreSQL        │
│  (Flask + Gunicorn) │     │  (Audit Database)   │
└──────────┬──────────┘     └─────────────────────┘
           │
           │ HTTP/REST
           ▼
┌─────────────────────────────────────────────────┐
│          Enhanced MCP Servers                    │
├─────────────────┬─────────────────┬─────────────┤
│ Infrastructure  │ Social Media    │ Threat Intel│
│     MCP        │     MCP         │     MCP     │
├─────────────────┼─────────────────┼─────────────┤
│ Financial Intel │ Technical Intel │             │
│     MCP        │     MCP         │             │
└─────────────────┴─────────────────┴─────────────┘
```

### Microservices Architecture

The platform consists of the following microservices:

1. **Frontend Service** (`osint-simple-frontend`)
   - React 18 single-page application
   - Material-UI components
   - Real-time WebSocket updates
   - PDF report generation

2. **Backend API Service** (`osint-backend`)
   - Flask REST API
   - JWT authentication
   - Investigation orchestration
   - Compliance validation

3. **Enhanced MCP Servers**
   - `mcp-infrastructure-enhanced:8021` - DNS, WHOIS, SSL analysis
   - `mcp-social-enhanced:8010` - Social media intelligence
   - `mcp-threat-enhanced:8020` - Threat intelligence
   - `mcp-financial-enhanced:8040` - Financial intelligence
   - `mcp-technical-enhanced:8050` - GitHub/GitLab analysis

4. **Data Services**
   - PostgreSQL 15 - Audit trail and investigation storage
   - Redis - Session management and caching
   - HashiCorp Vault - Secrets management

---

## Core Components

### 1. Investigation Orchestrator (`investigation_orchestrator.py`)

The brain of the system that manages the investigation lifecycle:

```python
class InvestigationOrchestrator:
    """Orchestrates OSINT investigations through multiple stages"""
    
    def __init__(self):
        self.mcp_manager = MCPClientManager()
        self.compliance_framework = ComplianceFramework()
        self.risk_assessment_engine = RiskAssessmentEngine()
        self.report_generator = ProfessionalReportGenerator()
```

**Investigation Stages:**
1. **Planning** (0-10%) - Target validation and scope definition
2. **Profiling** (10-20%) - Initial target reconnaissance
3. **Collecting** (20-60%) - Multi-source intelligence gathering
4. **Analyzing** (60-75%) - Data correlation and enrichment
5. **Verifying** (75-85%) - Compliance and accuracy checks
6. **Risk Assessment** (85-95%) - Threat scoring and confidence levels
7. **Report Generation** (95-100%) - Professional PDF creation

### 2. MCP Client Manager (`mcp_clients.py`)

Manages communication with enhanced MCP servers:

```python
async def gather_all_intelligence(self, target: str, investigation_type: str) -> Dict[str, List[IntelligenceResult]]:
    """Gather intelligence from all enhanced MCP servers"""
    
    results = {}
    async with aiohttp.ClientSession() as session:
        # Infrastructure Intelligence
        if investigation_type in ['comprehensive', 'infrastructure']:
            results['infrastructure'] = await self._call_enhanced_mcp(
                session, 'http://mcp-infrastructure-enhanced:8021/execute',
                [
                    {'tool': 'whois_lookup', 'parameters': {'domain': target}},
                    {'tool': 'dns_records', 'parameters': {'domain': target}},
                    {'tool': 'ssl_certificate_info', 'parameters': {'domain': target}}
                ]
            )
```

### 3. Enhanced MCP Servers

Each MCP server implements the Model Context Protocol with specialized tools:

#### Infrastructure MCP (`mcp-servers/infrastructure-enhanced/app.py`)
```python
TOOLS = {
    'whois_lookup': whois_lookup,      # Domain registration data
    'dns_records': dns_records,        # DNS A, MX, TXT, NS records
    'ssl_certificate_info': ssl_info,  # SSL certificate analysis
    'subdomain_enum': subdomain_enum   # Subdomain discovery
}
```

#### Social Media MCP (`mcp-servers/social-enhanced/app.py`)
```python
TOOLS = {
    'twitter_profile': twitter_profile,           # Twitter/X user data
    'reddit_profile': reddit_profile,             # Reddit user analysis
    'social_media_search': social_media_search   # Cross-platform search
}
```

### 4. Compliance Framework (`compliance_framework.py`)

Ensures regulatory compliance for all investigations:

```python
class ComplianceFramework:
    """Multi-jurisdiction compliance validation"""
    
    FRAMEWORKS = {
        'GDPR': GDPRCompliance(),      # EU General Data Protection
        'CCPA': CCPACompliance(),      # California Consumer Privacy
        'PIPEDA': PIPEDACompliance()   # Canadian Privacy Act
    }
    
    def assess_compliance(self, investigation: OSINTInvestigation) -> ComplianceAssessment:
        """Validate investigation against all applicable frameworks"""
```

### 5. Risk Assessment Engine (`risk_assessment_engine.py`)

Calculates threat scores and confidence levels:

```python
def assess_risk(self, investigation: OSINTInvestigation) -> RiskAssessment:
    """Calculate comprehensive risk score based on:
    - Infrastructure vulnerabilities
    - Social engineering susceptibility  
    - Data breach exposure
    - Malware/threat indicators
    - Financial risk factors
    """
```

---

## Technology Stack

### Backend Technologies
- **Language**: Python 3.11
- **Framework**: Flask 2.3.3
- **WSGI Server**: Gunicorn 21.2.0
- **Database ORM**: SQLAlchemy 2.0.21
- **Async Processing**: asyncio + aiohttp
- **Authentication**: PyJWT 2.8.0
- **API Documentation**: Flask-CORS 4.0.0

### Frontend Technologies
- **Framework**: React 18.2.0
- **Language**: TypeScript 5.0+
- **UI Library**: Material-UI 5.14.5
- **State Management**: Redux Toolkit
- **HTTP Client**: Axios 1.5.0
- **PDF Generation**: jsPDF 2.5.1

### Infrastructure Technologies
- **Container Runtime**: Docker 24.0+
- **Orchestration**: Kubernetes 1.28+
- **Package Manager**: Helm 3.12+
- **Database**: PostgreSQL 15.5
- **Caching**: Redis 7.2
- **Secrets**: HashiCorp Vault 1.15

### Intelligence Collection Libraries
- **WHOIS**: python-whois 0.8.0
- **DNS**: dnspython 2.4.2
- **SSL**: cryptography 41.0.4
- **Web Scraping**: BeautifulSoup4 4.12.2
- **HTTP**: requests 2.31.0

---

## Data Flow and Workflows

### 1. Investigation Creation Workflow

```mermaid
sequenceDiagram
    participant User
    participant Frontend
    participant Backend
    participant Orchestrator
    participant MCPs
    participant Database
    
    User->>Frontend: Create Investigation
    Frontend->>Backend: POST /api/investigations
    Backend->>Orchestrator: Start Investigation
    Orchestrator->>Database: Create Investigation Record
    Orchestrator->>MCPs: Gather Intelligence (Async)
    MCPs-->>Orchestrator: Return Results
    Orchestrator->>Database: Update Investigation
    Orchestrator->>Backend: Investigation Complete
    Backend->>Frontend: WebSocket Update
    Frontend->>User: Show Results
```

### 2. Intelligence Collection Flow

```python
# 1. Target Validation
target_profile = self._profile_target(investigation)

# 2. Parallel Intelligence Collection
async def collect_intelligence():
    tasks = []
    if 'infrastructure' in scope:
        tasks.append(collect_infrastructure_intelligence())
    if 'social' in scope:
        tasks.append(collect_social_intelligence())
    if 'threat' in scope:
        tasks.append(collect_threat_intelligence())
    
    results = await asyncio.gather(*tasks)
    return process_results(results)

# 3. Data Processing Pipeline
for source_name, results in intelligence_results.items():
    for result in results:
        processed_data = self._process_intelligence_data(result)
        structured_intel = self._structure_intelligence(processed_data)
        investigation.add_intelligence(structured_intel)

# 4. Risk Assessment
risk_score = self.risk_assessment_engine.calculate_score(investigation)

# 5. Report Generation
report = self.report_generator.generate_professional_report(investigation)
```

### 3. Data Processing Pipeline

The platform processes raw intelligence into structured data:

```python
# Raw MCP Response
{
    "tool": "whois_lookup",
    "result": {
        "domain": "example.com",
        "registrar": "GoDaddy.com, LLC",
        "created": "2017-12-22",
        "expires": "2027-12-22",
        "nameservers": ["ns1.example.com", "ns2.example.com"]
    }
}

# Structured Intelligence
{
    "domains": [{
        "domain": "example.com",
        "registrar": "GoDaddy.com, LLC",
        "creation_date": "2017-12-22",
        "expiration_date": "2027-12-22",
        "status": "active",
        "risk_indicators": []
    }],
    "infrastructure": {
        "name_servers": ["ns1.example.com", "ns2.example.com"],
        "hosting_provider": "GoDaddy",
        "ssl_grade": "A"
    }
}
```

---

## Security Architecture

### 1. Authentication & Authorization

```python
# JWT Token Structure
{
    "user_id": "admin",
    "username": "admin",
    "role": "admin",
    "clearance_level": "confidential",
    "exp": 1755221762,
    "iat": 1755192962
}

# Role-Based Access Control
ROLES = {
    'admin': ['create', 'read', 'update', 'delete', 'export'],
    'analyst': ['create', 'read', 'export'],
    'viewer': ['read']
}
```

### 2. API Security

- **CORS Configuration**: Restricted to specific origins
- **Rate Limiting**: 100 requests/minute per user
- **Input Validation**: All inputs sanitized and validated
- **SQL Injection Protection**: Parameterized queries via SQLAlchemy
- **XSS Protection**: Content Security Policy headers

### 3. Data Security

- **Encryption at Rest**: PostgreSQL with encrypted volumes
- **Encryption in Transit**: TLS 1.3 for all communications
- **Secrets Management**: HashiCorp Vault integration
- **Audit Logging**: Complete audit trail in PostgreSQL

```sql
-- Audit Schema
CREATE TABLE audit.events (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    user_id VARCHAR(255),
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    action VARCHAR(50),
    result VARCHAR(50),
    metadata JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

---

## Deployment Architecture

### 1. Kubernetes Resources

```yaml
# Namespace
apiVersion: v1
kind: Namespace
metadata:
  name: osint-platform

# Backend Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: osint-backend
  namespace: osint-platform
spec:
  replicas: 2
  selector:
    matchLabels:
      app: osint-backend
  template:
    spec:
      containers:
      - name: backend
        image: osint-platform/simple-backend:latest
        ports:
        - containerPort: 5000
        env:
        - name: POSTGRES_URL
          value: "postgresql://postgres:password@postgresql:5432/osint_audit"
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

### 2. Service Mesh Architecture

```yaml
# Service Definition
apiVersion: v1
kind: Service
metadata:
  name: osint-backend
  namespace: osint-platform
spec:
  type: ClusterIP
  ports:
  - port: 5000
    targetPort: 5000
    protocol: TCP
  selector:
    app: osint-backend
```

### 3. Scaling Configuration

```yaml
# Horizontal Pod Autoscaler
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: osint-backend-hpa
  namespace: osint-platform
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: osint-backend
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

---

## API Documentation

### Authentication Endpoints

#### POST /api/auth/login
```json
Request:
{
    "username": "admin",
    "password": "admin123"
}

Response:
{
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "message": "Login successful",
    "user": {
        "user_id": "admin",
        "username": "admin",
        "role": "admin",
        "clearance_level": "confidential"
    }
}
```

### Investigation Endpoints

#### POST /api/investigations
```json
Request:
{
    "target": "example.com",
    "investigation_type": "comprehensive",
    "priority": "high",
    "scope": {
        "include_infrastructure": true,
        "include_social_media": true,
        "include_threat_intelligence": true,
        "max_investigation_hours": 24
    }
}

Response:
{
    "id": "605ba974-9a88-4921-855e-c9dbedc2b3d8",
    "status": "planning",
    "message": "OSINT investigation started successfully",
    "api_status": {
        "available_apis": {
            "infrastructure": 1,
            "social_media": 1,
            "threat_intelligence": 1
        }
    },
    "progress": {
        "overall_progress": 0.1,
        "stage": "planning",
        "current_activity": "Validating investigation parameters"
    }
}
```

#### GET /api/investigations/{id}
Returns complete investigation details including all collected intelligence.

#### GET /api/investigations/{id}/report
Generates and returns a professional PDF report.

### System Status Endpoints

#### GET /api/system/status
```json
Response:
{
    "service": "Enterprise OSINT Platform",
    "status": "operational",
    "components": {
        "postgresql": {"connected": true},
        "vault": {"connected": false},
        "orchestrator": {"status": "running"},
        "mcp_servers": {
            "infrastructure": "online",
            "social_media": "online",
            "threat_intel": "online"
        }
    },
    "metrics": {
        "active_investigations": 3,
        "total_reports": 42,
        "api_availability": "3/5"
    }
}
```

---

## Configuration Guide

### 1. Environment Variables

```bash
# Database Configuration
POSTGRES_URL=postgresql://user:pass@host:5432/osint_audit
POSTGRES_HOST=postgresql
POSTGRES_PORT=5432
POSTGRES_USER=postgres
POSTGRES_PASSWORD=secure_password
POSTGRES_DB=osint_audit

# Security Configuration
JWT_SECRET_KEY=your-secret-key-change-in-production
VAULT_ADDR=http://vault:8200
VAULT_TOKEN=dev-only-token

# MCP Server URLs (Internal Kubernetes)
MCP_INFRASTRUCTURE_URL=http://mcp-infrastructure-enhanced:8021
MCP_SOCIAL_URL=http://mcp-social-enhanced:8010
MCP_THREAT_URL=http://mcp-threat-enhanced:8020
MCP_FINANCIAL_URL=http://mcp-financial-enhanced:8040
MCP_TECHNICAL_URL=http://mcp-technical-enhanced:8050

# External API Keys (Store in Vault for Production)
OPENAI_API_KEY=your-openai-key
TWITTER_BEARER_TOKEN=your-twitter-token
SHODAN_API_KEY=your-shodan-key
VIRUSTOTAL_API_KEY=your-virustotal-key
REDDIT_CLIENT_ID=your-reddit-client
REDDIT_CLIENT_SECRET=your-reddit-secret

# Application Configuration
FLASK_ENV=production
LOG_LEVEL=INFO
WORKER_PROCESSES=4
WORKER_TIMEOUT=300
```

### 2. Kubernetes Secrets

```bash
# Create API Keys Secret
kubectl create secret generic osint-api-keys \
  --namespace=osint-platform \
  --from-literal=openai-api-key=$OPENAI_API_KEY \
  --from-literal=twitter-bearer-token=$TWITTER_BEARER_TOKEN \
  --from-literal=shodan-api-key=$SHODAN_API_KEY \
  --from-literal=virustotal-api-key=$VIRUSTOTAL_API_KEY

# Create Database Secret
kubectl create secret generic postgresql-secret \
  --namespace=osint-platform \
  --from-literal=POSTGRES_PASSWORD=$POSTGRES_PASSWORD
```

### 3. Helm Values Configuration

```yaml
# helm/osint-platform/values.yaml
global:
  namespace: osint-platform
  environment: production

backend:
  replicas: 3
  image:
    repository: osint-platform/simple-backend
    tag: latest
    pullPolicy: Always
  resources:
    requests:
      memory: "512Mi"
      cpu: "200m"
    limits:
      memory: "1Gi"
      cpu: "1000m"

frontend:
  replicas: 2
  image:
    repository: osint-platform/simple-frontend
    tag: latest

postgresql:
  enabled: true
  auth:
    database: osint_audit
    username: postgres
  persistence:
    enabled: true
    size: 50Gi

mcpServers:
  infrastructure:
    enabled: true
    replicas: 2
  social:
    enabled: true
    replicas: 2
  threat:
    enabled: true
    replicas: 1
```

---

## Code Structure

### Backend Structure (`simple-backend/`)

```
simple-backend/
├── app.py                              # Main Flask application
├── models.py                           # SQLAlchemy data models
├── investigation_orchestrator.py       # Investigation workflow engine
├── mcp_clients.py                      # MCP server communication
├── compliance_framework.py             # Regulatory compliance
├── risk_assessment_engine.py           # Risk scoring algorithms
├── professional_report_generator.py    # PDF report generation
├── audit_report_generator.py           # Audit trail reports
├── postgres_audit_client.py            # Database audit logging
├── api_connection_monitor.py           # External API monitoring
├── vault_client.py                     # HashiCorp Vault integration
├── requirements.txt                    # Python dependencies
└── Dockerfile                          # Container definition
```

### Frontend Structure (`simple-frontend/`)

```
simple-frontend/
├── index.html                          # Main SPA entry point
├── css/
│   └── styles.css                      # Application styles
├── js/
│   ├── app.js                          # Main application logic
│   ├── api.js                          # Backend API client
│   ├── components.js                   # React components
│   └── utils.js                        # Utility functions
├── nginx.conf                          # Nginx configuration
├── package.json                        # Node dependencies
└── Dockerfile                          # Container definition
```

### MCP Server Structure (`mcp-servers/*/`)

```
mcp-servers/infrastructure-enhanced/
├── app.py                              # Flask MCP server
├── requirements.txt                    # Python dependencies
└── Dockerfile                          # Container definition

# Each MCP server follows the same structure with specialized tools
```

### Key Data Models

```python
@dataclass
class OSINTInvestigation:
    """Core investigation model"""
    id: str
    target_profile: TargetProfile
    investigation_type: str
    status: str
    progress: InvestigationProgress
    infrastructure_intelligence: Optional[InfrastructureIntelligence]
    social_intelligence: Optional[SocialIntelligence]
    threat_intelligence: Optional[ThreatIntelligence]
    financial_intelligence: Optional[FinancialIntelligence]
    technical_intelligence: Optional[TechnicalIntelligence]
    risk_assessment: Optional[RiskAssessment]
    compliance_reports: List[ComplianceAssessment]
    key_findings: List[str]
    recommendations: List[str]

@dataclass
class IntelligenceResult:
    """Standardized intelligence data format"""
    source: str                    # e.g., "whois_lookup_enhanced"
    data_type: str                 # e.g., "infrastructure"
    target: str                    # Investigation target
    raw_data: Dict[str, Any]       # Original data from source
    processed_data: Dict[str, Any] # Normalized data
    confidence_score: float        # 0.0 to 1.0
    timestamp: datetime
    metadata: Dict[str, Any]       # Additional context
```

---

## Production Deployment Checklist

### Pre-Deployment
- [ ] Generate secure JWT secret key
- [ ] Configure HashiCorp Vault with production policies
- [ ] Obtain API keys for all external services
- [ ] Set up PostgreSQL with encrypted storage
- [ ] Configure TLS certificates for all services
- [ ] Review and update CORS policies
- [ ] Set appropriate resource limits

### Deployment Steps
1. Create Kubernetes namespace
2. Deploy PostgreSQL with persistent storage
3. Deploy Redis for session management
4. Deploy Vault and configure secrets
5. Deploy enhanced MCP servers
6. Deploy backend API service
7. Deploy frontend service
8. Configure ingress/load balancer
9. Set up monitoring and alerting
10. Configure backup strategies

### Post-Deployment
- [ ] Verify all health checks pass
- [ ] Test investigation workflow end-to-end
- [ ] Validate compliance frameworks
- [ ] Configure log aggregation
- [ ] Set up performance monitoring
- [ ] Document operational procedures
- [ ] Train operations team

---

## Troubleshooting Guide

### Common Issues

1. **MCP Connection Failures**
   - Check service DNS resolution
   - Verify network policies
   - Confirm MCP server health endpoints

2. **Investigation Stuck in Processing**
   - Check MCP server logs
   - Verify external API availability
   - Review timeout configurations

3. **Empty Intelligence Results**
   - Confirm MCP data processing logic
   - Check field mapping in orchestrator
   - Verify API responses

4. **Authentication Failures**
   - Validate JWT secret configuration
   - Check token expiration
   - Verify CORS settings

### Debug Commands

```bash
# Check all pods
kubectl get pods -n osint-platform

# View backend logs
kubectl logs -f deployment/osint-backend -n osint-platform

# Test MCP connectivity
kubectl exec -it deployment/osint-backend -n osint-platform -- curl http://mcp-infrastructure-enhanced:8021/health

# Database connection test
kubectl exec -it deployment/osint-backend -n osint-platform -- psql $POSTGRES_URL -c "SELECT 1"
```

---

## Performance Optimization

### Database Optimization
- Indexed columns: investigation_id, target, status, created_at
- Connection pooling: Max 20 connections per pod
- Query optimization: Lazy loading for large datasets
- Partitioning: Monthly partitions for audit tables

### Caching Strategy
- Redis TTL: 15 minutes for investigation data
- Frontend caching: Service worker for static assets
- API response caching: ETag headers for unchanged data

### Scaling Guidelines
- Backend: 1 pod per 50 concurrent investigations
- MCP Servers: 1 pod per 100 requests/minute
- PostgreSQL: Vertical scaling for < 1TB data
- Redis: 1GB RAM per 10,000 active sessions

---

## Future Enhancements

### Planned Features
1. **Machine Learning Integration**
   - Anomaly detection in infrastructure patterns
   - Predictive risk scoring
   - Natural language processing for reports

2. **Additional Intelligence Sources**
   - Dark web monitoring
   - Blockchain analysis
   - IoT device discovery

3. **Enterprise Features**
   - Multi-tenancy support
   - SAML/OAuth integration
   - Advanced RBAC with custom roles

4. **Operational Improvements**
   - GraphQL API endpoint
   - Real-time collaboration
   - Mobile application

---

## Conclusion

The Enterprise OSINT Platform represents a comprehensive, production-ready solution for open-source intelligence gathering. Its microservices architecture, compliance frameworks, and extensible design make it suitable for enterprise deployment while maintaining the flexibility needed for diverse intelligence requirements.

For questions or contributions, please refer to the project repository and documentation.