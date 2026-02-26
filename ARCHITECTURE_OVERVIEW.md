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
- **Graph Intelligence**: Palantir-style relationship analysis, community detection, blast radius analysis

---

## System Architecture

### High-Level Architecture

```
┌─────────────────────┐
│   Web Interface     │
│  (React 18 + JS)    │
└──────────┬──────────┘
           │ HTTPS/REST
           ▼
┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────┐
│   Backend API       │────▶│   PostgreSQL 15     │     │   Redis Cluster     │
│  (Flask + JWT Auth) │     │  (Audit Database)   │     │  (Session Cache)    │
└──────────┬──────────┘     └─────────────────────┘     └─────────────────────┘
           │
           ├────────────────────────┬─────────────────────┬─────────────────────┐
           ▼                        ▼                     ▼                     ▼
┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐
│   Monitoring Stack  │  │   Health Monitor    │  │   HashiCorp Vault   │  │   Job Queue         │
│ (Prometheus/Grafana)│  │  (5-min checks)     │  │  (Secret Management)│  │  (Background Tasks) │
└─────────────────────┘  └─────────────────────┘  └─────────────────────┘  └─────────────────────┘
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

3. **Enhanced MCP Servers** (FastAPI-based)
   - `mcp-infrastructure-enhanced:8021` - DNS, WHOIS, SSL, Certificate Transparency
   - `mcp-social-enhanced:8010` - Twitter/X, Reddit, LinkedIn intelligence
   - `mcp-threat-enhanced:8020` - Multi-source threat aggregation (VirusTotal, Shodan, AbuseIPDB)
   - `mcp-financial-enhanced:8040` - SEC filings, financial analysis
   - `mcp-technical-enhanced:8050` - AI-powered analysis with GPT-4

4. **Data Services**
   - PostgreSQL 15 - Audit trail and investigation storage
   - Redis Cluster - Session management and caching
   - HashiCorp Vault - Secrets management

5. **Monitoring & Observability Stack**
   - Prometheus - Metrics collection with 15-day retention
   - Grafana - Pre-configured dashboards for OSINT operations
   - Health Monitor - Automated health checks (5-minute intervals)
   - Custom Metrics Exporter - OSINT-specific metrics

---

## Core Components

### 0. Analytic Tradecraft Engine (`analytic_tradecraft.py`)

Implements intelligence community (IC) structured analytic techniques for rigorous analysis:

**NATO/Admiralty Scale:**
- Source Reliability: A-F grades (Completely Reliable to Cannot Be Judged)
- Information Credibility: 1-6 grades (Confirmed to Cannot Be Judged)
- Double-matrix ratings: Combines both dimensions for confidence assessment

**Intelligence Community Standards:**
- IC Confidence Levels: High/Moderate/Low with ICD 203 vocabulary
- Sherman Kent "Words of Estimative Probability" (WEP) scale
- Structured confidence justification with controlling factors

**Analysis of Competing Hypotheses (ACH):**
- Evidence × Hypothesis matrix with Heuer diagnostic scoring
- Identifies disconfirming vs. supporting evidence
- Calculates diagnostic consistency for each hypothesis

**Anti-Confirmation Bias Mechanisms:**
- `AlternativeExplanation` model enforces documenting rejected alternatives
- `DevilsAdvocacy` model captures designated dissent
- `AnalyticConclusion` with mandatory caveats and limitations

**Intelligence Statement Generator:**
- Auto-generates IC-standard conclusion statements
- Format: "We assess with [confidence] that [statement] because [key evidence]"
- Includes key assumptions, alternative views, and confidence justification

**Persistence:**
- JSON-based storage in APP_DATA_DIR (no database changes needed)
- Survives container restarts
- Full audit trail of analytic decisions

### 1. Real-Time Monitoring Engine (`alert_engine.py`, `monitoring_scheduler.py`)

Continuous infrastructure surveillance with automated alerting:

**Watchlist Management:**
- 9 target types: domain, IP, email, keyword, registrant, certificate_subject, threat_actor, CIDR, ASN
- Per-entry enabled/disabled toggle
- Configurable check intervals (hourly to weekly)
- Custom descriptions and tags for organization

**Infrastructure Snapshots:**
- Point-in-time records: DNS A/MX/TXT/NS records, SSL certificates (crt.sh), open ports (Shodan), WHOIS data, IP reputation
- Diff detection: Compares current snapshot vs. previous baseline
- Change tracking: Detailed before/after records for forensics

**14 Alert Types:**
- DNS changes: new_record, removed, changed
- Certificates: new_certificate, expiry_warning
- Port/Service: shodan_port_change, new_service
- Registrant: registrant_match, new_subdomain
- Reputation: ip_reputation_change, threat_actor_active
- Domain: whois_change, domain_expiry_warning

**MonitoringScheduler Daemon:**
- Background thread with 60s tick interval
- Per-watchlist check scheduling (1h-7d intervals with drift prevention)
- On-demand trigger capability
- Alert status tracking: new → acknowledged → in_progress → resolved/dismissed

**AlertStore Persistence:**
- JSON-based with filtering by watchlist/status/severity
- Full alert history with creation/modification timestamps
- Severity levels: info, low, medium, high, critical

### 2. Service Configuration Manager (`service_config.py`)

Centralized 19-service catalog with in-app API key management:

**Service Tiers:**
- Free (9 services): DNS, WHOIS, crt.sh, URLScan, HIBP password check, spaCy NLP, etc.
- Freemium (6 services): VirusTotal, Shodan, AbuseIPDB, OTX, etc.
- Paid (4 services): Dehashed, Hudson Rock Cavalier, Mandiant Advantage, etc.

**Zero-Configuration Services:**
- 9 services work without API keys using free/public endpoints
- Intelligent fallback: Full functionality even if paid keys missing
- Mock mode for demo/testing environments

**Dynamic Configuration:**
- In-app key management via `/api/settings/services` endpoints
- Keys persisted in service_config.json
- Auto-loaded into os.environ on startup
- Service enable/disable toggles
- Demo/Live mode switching (affects service endpoints)

**Service Metadata:**
- 19-service catalog with category, tier, docs_url, signup_url
- Rate limit notes (e.g., "4 req/min on free plan")
- Tier notes (e.g., "500 req/day free")
- enabled_by_default boolean for each service

### 3. Credential Intelligence Service (`credential_intel_service.py` + `blueprints/credentials.py`)

Multi-source credential breach detection and password security analysis:

**Breach Database APIs:**
- HIBP (Have I Been Pwned): Breach and paste exposure searches (free tier)
- Dehashed: Leaked credential search via email/domain (API key required)
- Hudson Rock Cavalier: Infostealer victim database and compromised email lookups
- Paste Site Monitoring: Continuous monitoring of paste dumps for credential exposure

**Password Security:**
- k-Anonymity check: Only SHA-1 prefix (first 5 chars) sent to HIBP
- Full password never leaves client or server
- Exposed count with severity scoring
- Hash type detection (MD5, SHA-1, SHA-256, bcrypt)

**Risk Scoring:**
- Per-email exposure severity: 0-100 score
- Categories: none (0-20), low (21-40), medium (41-60), high (61-80), critical (81-100)
- Breach age weighting: Recent breaches score higher
- Compromise context: Malware vs. password manager vs. public leak

**Investigation Integration:**
- Link credential exposure to investigation targets
- Export exposure list in reports
- Automated follow-up suggestions

**MCP Server:**
- Dedicated `mcp-servers/credential-intel/` FastAPI service
- Async batch processing for multiple email/domain checks
- Caching of HIBP results (24h TTL)

### 4. NLP Pipeline (`nlp_pipeline.py`)

Natural language processing for intelligence enrichment:

**Entity Extraction:**
- spaCy-based NER: Persons, Organizations, Locations, GPEs
- Custom patterns: IP addresses, domains, file hashes, URLs, email addresses
- Confidence scoring per entity

**Text Classification:**
- Threat intelligence report classification: malware, phishing, C2, data theft, etc.
- Sentiment analysis: Positive, negative, neutral
- Language detection
- OCR text processing from documents

**Entity Relationship Inference:**
- Co-occurrence relationships from extracted entities
- Context-aware linking (e.g., "person works at organization")
- Relationship confidence scoring

**Processing Pipeline:**
- Batch processing of investigation summaries
- Report text extraction and analysis
- Automated keyword tagging
- Feed enrichment with entity metadata

### 5. STIX/MISP Export (`stix_export.py`)

Standards-compliant threat intelligence export:

**STIX 2.1 Bundle Generation:**
- Converts investigation entities to STIX objects
- Supported types: Indicator, Malware, AttackPattern, ThreatActor, Campaign, Infrastructure
- Relationship export with STIX SROs (Relationship objects)
- Bundle metadata: created timestamp, created_by_ref, labels, external_references

**MISP Event Export:**
- Converts investigation to MISP event format
- Attribute types: domain, ip-dst, hostname, email-src, file|md5, url, etc.
- Event tagging with MITRE ATT&CK, malware families, threat actors
- Push-to-MISP integration (HTTP POST to MISP instance)

**Enterprise Compliance:**
- TLP marking levels (TLP:AMBER, TLP:GREEN, etc.)
- Confidence score mapping to STIX pattern
- Audit trail: who created, when, why
- Version control for indicator updates

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

### 3. Job Queue System (`job_queue.py`)

Background task management for asynchronous operations:

```python
class JobQueueManager:
    """Manages background jobs for long-running operations"""
    
    def __init__(self):
        self.jobs = {}
        self.executor = ThreadPoolExecutor(max_workers=4)
    
    async def submit_job(self, job_type: str, job_data: dict) -> str:
        """Submit a job for background processing"""
        job_id = str(uuid.uuid4())
        future = self.executor.submit(self._process_job, job_type, job_data)
        self.jobs[job_id] = {
            'future': future,
            'status': 'pending',
            'created_at': datetime.utcnow()
        }
        return job_id
```

**Note**: Currently using a mock implementation for Docker compatibility. Production deployment should use Celery or similar.

### 4. Enhanced MCP Servers

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

### 6. Intelligence Correlation Engine (`intelligence_correlation.py`)

Cross-source entity extraction and relationship mapping:

```python
class IntelligenceCorrelationEngine:
    """Extract entities and build relationships across sources"""

    def correlate(self, investigation_data: dict) -> CorrelationResult:
        """
        - Extract entities (domains, IPs, emails, hashes)
        - Map relationships between entities
        - Build investigation timeline
        - Calculate confidence scores
        """
```

### 7. Advanced Analysis Module (`advanced_analysis.py`)

MITRE ATT&CK mapping and executive insights:

```python
class AdvancedAnalysisEngine:
    """Advanced threat analysis with MITRE framework"""

    def analyze(self, investigation_data: dict) -> AdvancedAnalysis:
        """
        - Map findings to MITRE ATT&CK tactics (14 covered)
        - Generate risk scores (6 categories)
        - Create executive summary with key findings
        - Perform trend analysis
        """
```

### 8. Graph Intelligence Engine (`graph_intelligence/`)

Palantir-style graph analytics for advanced relationship analysis:

```python
# Entity and relationship modeling
class GraphEntity:
    """35+ entity types: Person, Organization, Domain, IP, etc."""
    entity_id: str
    entity_type: EntityType
    properties: Dict[str, Any]
    risk_score: float

class GraphRelationship:
    """45+ relationship types: OWNS, OPERATES, CONNECTS_TO, etc."""
    source_id: str
    target_id: str
    relationship_type: RelationshipType
    properties: Dict[str, Any]
```

**Algorithm Modules:**
- `algorithms/centrality.py` - PageRank, betweenness, closeness, eigenvector, harmonic, katz
- `algorithms/paths.py` - Shortest path, all paths, reachability, pivot finding
- `algorithms/community.py` - Louvain, label propagation, k-core, clustering coefficient
- `algorithms/similarity.py` - Jaccard, Adamic-Adar, cosine, SimRank
- `algorithms/anomaly.py` - Degree anomalies, bridge detection, hub/authority, star patterns
- `algorithms/influence.py` - Independent cascade, linear threshold, SIR/SIS epidemic, blast radius

**Key Features:**
- Neo4j database integration with mock fallback for development
- Investigation-to-graph synchronization
- Blast radius analysis for compromise impact assessment
- Entity similarity search across investigations

### 9. Blueprint Architecture

Modular route organization for the Flask backend:

```python
# blueprints/auth.py - Authentication
@bp.route('/api/auth/login', methods=['POST'])
def login(): ...

# blueprints/health.py - Health/Monitoring
@bp.route('/health', methods=['GET'])
def health_check(): ...

# shared.py - Services singleton
class Services:
    orchestrator: InvestigationOrchestrator
    compliance_engine: ComplianceFramework
    vault_client: VaultClient
    # ... shared across blueprints
```

**Current Status:** Phase 1 complete (auth, health blueprints). Phase 2 planned for remaining routes.

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
- **Language**: TypeScript 5.3+
- **UI Library**: Material-UI 5.14.5
- **State Management**: Redux Toolkit
- **HTTP Client**: Axios 1.5.0
- **PDF Generation**: jsPDF 2.5.1
- **Testing**: Jest, React Testing Library (350+ tests)
- **Accessibility**: WCAG 2.1 compliant components

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
├── app.py                              # Main Flask application (60+ endpoints)
├── shared.py                           # Services singleton container
├── models.py                           # SQLAlchemy data models
├── blueprints/                         # Flask Blueprint modules
│   ├── __init__.py                     # Blueprint package
│   ├── auth.py                         # Authentication routes (JWT)
│   ├── health.py                       # Health checks, K8s probes
│   ├── admin.py                        # Admin routes
│   ├── investigations.py                # Investigation CRUD + orchestration
│   ├── reports.py                      # Report generation and export
│   ├── analysis.py                     # Intelligence analysis endpoints
│   ├── intelligence.py                 # Intelligence correlation endpoints
│   ├── risk.py                         # Risk assessment endpoints
│   ├── compliance.py                   # Compliance framework assessment
│   ├── graph.py                        # Graph intelligence endpoints
│   ├── tradecraft.py                   # Analytic tradecraft (NATO/ACH/Devil's Advocacy)
│   ├── monitoring.py                   # Watchlist and alert management
│   ├── credentials.py                  # Credential intelligence endpoints (HIBP, Dehashed, etc)
│   ├── nlp.py                          # NLP entity extraction and classification
│   ├── stix.py                         # STIX/MISP export endpoints
│   └── settings.py                     # Service configuration and API key management
├── utils/
│   └── startup_validation.py           # Security validation at startup
├── core_modules/                       # Standalone service modules
│   ├── analytic_tradecraft.py          # NATO/Admiralty scale, ACH matrix, IC confidence
│   ├── alert_engine.py                 # Watchlist entries, infrastructure snapshots
│   ├── service_config.py               # 19-service catalog + API key manager
│   ├── credential_intel_service.py     # HIBP, Dehashed, Hudson Rock integration
│   ├── nlp_pipeline.py                 # spaCy NER, text classification
│   ├── stix_export.py                  # STIX 2.1 bundle + MISP event export
│   ├── monitoring_scheduler.py         # Background monitoring daemon
│   ├── compliance_framework.py         # Regulatory compliance (GDPR/CCPA/HIPAA/SOX)
│   ├── investigation_orchestrator.py   # 7-stage investigation workflow
│   ├── intelligence_correlation.py     # Entity correlation engine
│   ├── advanced_analysis.py            # MITRE ATT&CK mapping, risk scoring
│   ├── risk_assessment_engine.py       # Threat scoring and confidence
│   └── professional_report_generator.py # PDF report generation
├── graph_intelligence/                 # Palantir-style graph analytics
│   ├── models.py                       # 35+ entity types, 45+ relationships
│   ├── neo4j_client.py                 # Graph database client + mock
│   ├── api.py                          # REST endpoints
│   ├── sync.py                         # Investigation-to-graph sync
│   └── algorithms/                     # Graph algorithms (~6,300 lines)
│       ├── centrality.py               # PageRank, betweenness, closeness
│       ├── paths.py                    # Shortest path, reachability
│       ├── community.py                # Louvain, label propagation
│       ├── similarity.py               # Jaccard, Adamic-Adar, SimRank
│       ├── anomaly.py                  # Anomaly detection patterns
│       └── influence.py                # Cascade, epidemic, blast radius
├── mcp_clients.py                      # MCP server communication
├── observability.py                    # OpenTelemetry, tracing
├── problem_json.py                     # RFC 7807 error handling
├── expanded_data_sources.py            # 6 intelligence source collectors
├── demo_data.py                        # Demo mode data provider
├── mode_manager.py                     # Demo/Live mode switching
├── vault_client.py                     # HashiCorp Vault integration
├── cache_service.py                    # Redis caching layer
├── tests/                              # Test suite (220+ functions)
│   ├── unit/                           # Unit tests
│   ├── integration/                    # Integration tests
│   └── graph_intelligence/             # Graph module tests
├── requirements.txt                    # Python dependencies
└── Dockerfile                          # Container definition
```

### Modern Frontend Structure (`frontend/`)

```
frontend/
├── src/
│   ├── pages/                          # Application pages (16 total)
│   │   ├── Dashboard.tsx               # Main dashboard with investigation overview
│   │   ├── Investigations.tsx           # Investigation list with filtering
│   │   ├── NewInvestigation.tsx         # Guided investigation creation
│   │   ├── InvestigationDetail.tsx      # Full investigation details + tabs
│   │   ├── Reports.tsx                  # Report history and generation
│   │   ├── AnalyticWorkbench.tsx        # 4-tab: Intel Items, Hypotheses, ACH Matrix, Conclusions
│   │   ├── Monitoring.tsx               # Watchlist management + alert feed (30s refresh)
│   │   ├── CredentialIntelligence.tsx   # Email/domain/password exposure checks
│   │   ├── ThreatIntelligence.tsx       # IOC feed + actor profiles overview
│   │   ├── ThreatAnalysis.tsx           # Detailed threat analysis with MITRE mapping
│   │   ├── GraphIntelligence.tsx        # Graph visualization + centrality/community analysis
│   │   ├── CompliancePage.tsx           # GDPR/CCPA/HIPAA/SOX assessment cards
│   │   ├── TeamPage.tsx                 # Team management (placeholder)
│   │   ├── DataSourcesPage.tsx          # Source category browser + Settings link
│   │   ├── Settings.tsx                 # Global settings + API key management
│   │   └── Login.tsx                    # JWT authentication
│   ├── components/
│   │   ├── common/                     # Reusable UI components
│   │   │   ├── Button.tsx              # Button with 6 variants, 3 sizes
│   │   │   ├── Card.tsx                # Card with CardStat subcomponent
│   │   │   ├── Modal.tsx               # Modal, ConfirmationModal
│   │   │   ├── FormField.tsx           # Text, Select, Checkbox, Switch, Textarea
│   │   │   ├── StatusIndicator.tsx     # Status badges, RiskLevelIndicator
│   │   │   ├── Loading.tsx             # Spinner, ProgressBar, Skeletons
│   │   │   └── Toast.tsx               # Toast notifications with provider
│   │   ├── layout/                     # Layout components
│   │   │   ├── Header.tsx              # Search, notifications, user menu
│   │   │   ├── Sidebar.tsx             # Collapsible navigation
│   │   │   └── Layout.tsx              # Main wrapper with PageWrapper
│   │   ├── visualizations/             # Chart and graph components
│   │   │   ├── ThreatMatrix.tsx        # MITRE ATT&CK heatmap
│   │   │   ├── RiskGauge.tsx           # Risk score gauge chart
│   │   │   ├── TimelineChart.tsx       # Investigation timeline visualization
│   │   │   ├── EntityGraph.tsx         # Interactive graph visualization
│   │   │   └── ComplianceHeatmap.tsx   # Compliance framework coverage
│   │   └── a11y/                       # Accessibility components
│   │       ├── SkipLinks.tsx           # Skip navigation for keyboard users
│   │       ├── VisuallyHidden.tsx      # Screen reader only content
│   │       ├── ErrorBoundary.tsx       # Error handling with retry
│   │       └── FocusRing.tsx           # Consistent focus indicators
│   ├── hooks/                          # Custom React hooks
│   │   ├── useKeyboardNavigation.ts    # Arrow key navigation
│   │   ├── useFocusTrap.ts             # Modal focus trapping
│   │   ├── useAnnounce.ts              # ARIA live announcements
│   │   ├── useMediaQuery.ts            # Responsive breakpoints
│   │   └── useInvestigationPolling.ts  # Real-time investigation status updates
│   ├── utils/                          # Utilities
│   │   ├── theme.ts                    # Design system tokens
│   │   ├── validation.ts               # Form validators (15+)
│   │   └── a11y.ts                     # Color contrast, focus helpers
│   ├── types/                          # TypeScript definitions
│   │   └── index.ts                    # 80+ interfaces
│   └── __tests__/                      # Test suites (350+ tests)
├── package.json                        # Node dependencies
└── tsconfig.json                       # TypeScript configuration
```

**Frontend Capabilities (Updated):**
- 16 pages supporting all new backend modules
- AnalyticWorkbench: NATO/Admiralty scale ratings, ACH matrix, hypothesis tracking
- Monitoring dashboard: Real-time watchlist feed with 30s auto-refresh, alert management
- Credential intelligence: Multi-source breach checking with severity scoring
- Tradecraft visualization: Confidence statements, alternative explanations, devil's advocacy
- STIX/MISP export: One-click threat intelligence standard export
- Service settings: In-app API key management for 19-service catalog

### Legacy Frontend Structure (`simple-frontend/`)

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