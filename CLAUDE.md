# CLAUDE.md

Guidance for Claude Code when working with this repository.

---

> **CANONICAL BACKEND: `simple-backend/`**
>
> This repo contains **three** backend directories.  Only one is active:
>
> | Directory | Status | Notes |
> |-----------|--------|-------|
> | `simple-backend/` | ✅ **Active — use this** | Flask API, 500+ tests, full feature set |
> | `fastapi-backend/` | ❌ Archived | Incomplete FastAPI port — see `fastapi-backend/ARCHIVED.md` |
> | `backend/` | ❌ Archived | Early prototype — see `backend/ARCHIVED.md` |
>
> Always work in `simple-backend/`.  Never route CI, Docker builds, or Kubernetes
> manifests to `fastapi-backend/` or `backend/`.

---

## Quick Reference

```bash
./start.sh demo    # Start demo mode (no API keys needed)
./start.sh local   # Start with optional API keys
./start.sh k8s     # Deploy to Kubernetes
./start.sh stop    # Stop all services
```

## Repository Structure

```
Enterprise-OSINT-Platform/
├── simple-backend/          # ✅ CANONICAL Flask REST API (Python 3.11+)
│   ├── blueprints/          # 15 Flask Blueprints (see list below)
│   ├── graph_intelligence/  # Palantir-style graph analytics
│   ├── tests/               # Backend tests (500+ functions)
│   └── utils/               # Startup validation, utilities
├── frontend/                # Modern React Frontend (TypeScript)
│   ├── src/components/      # Reusable UI components
│   ├── src/hooks/           # Custom React hooks
│   ├── src/pages/           # 16 full-page views (routed in App.tsx)
│   ├── src/utils/           # Theme, validation, a11y utilities
│   └── src/__tests__/       # Frontend tests (484 tests)
├── simple-frontend/         # Legacy React SPA (HTML/JS)
├── mcp-servers/             # Intelligence microservices (FastAPI/Flask)
│   ├── infrastructure-advanced/  # Port 8021
│   ├── threat-aggregator/        # Port 8020
│   ├── ai-analyzer/              # Port 8050
│   ├── social-media-enhanced/    # Port 8010
│   ├── financial-enhanced/       # Port 8040
│   ├── credential-intel/         # Port 8030
│   └── tests/               # MCP smoke tests (no API keys needed)
├── k8s/                     # Kubernetes manifests (54+ files)
├── scripts/                 # Utility scripts (deploy/, dev/, maintenance/)
├── docs/                    # Extended documentation
├── start.sh                 # One-command setup
├── docker-compose.demo.yml  # Demo deployment
│
│   --- ARCHIVED (do not use) ---
├── fastapi-backend/         # ❌ Archived FastAPI port (incomplete)
└── backend/                 # ❌ Archived early prototype
```

## Core Components

### Backend (`simple-backend/`)

**Core Application:**
- `app.py` — Flask REST API, 15 blueprint registrations, 70+ endpoints, JWT auth
- `shared.py` — Services singleton container
- `models.py` — Data models and dataclasses (IntelligenceResult, IntelligenceResults, etc.)
- `conftest.py` — pytest fixtures (sets APP_DATA_DIR, JWT_SECRET_KEY, etc. before import)

**Blueprint Architecture (15 blueprints — all registered in app.py):**

| Blueprint | Prefix | Purpose |
|-----------|--------|---------|
| `auth.py` | `/api/auth/*` | JWT login, token refresh, /me |
| `health.py` | `/health`, `/ready`, `/metrics` | K8s probes, Prometheus metrics |
| `admin.py` | `/api/mcp/*`, `/api/stats`, `/api/jobs/*` | Admin, MCP status, job queue |
| `investigations.py` | `/api/investigations/*` | CRUD, list, status |
| `reports.py` | `/api/investigations/*/report`, `/api/reports/*` | Report generation |
| `compliance.py` | `/api/compliance/*` | GDPR/CCPA/HIPAA/SOX frameworks |
| `risk.py` | `/api/risk/*` | Risk assessment engine |
| `intelligence.py` | `/api/intelligence/*`, `/api/correlation/*` | Entity correlation |
| `analysis.py` | `/api/analysis/*`, `/api/mitre/*` | MITRE ATT&CK mapping |
| `graph.py` | `/api/investigations/*/graph/*`, `/api/graph/*` | Graph intelligence |
| `nlp.py` | `/api/nlp/*` | NLP pipeline (entity extraction, text analysis) |
| `stix.py` | `/api/investigations/*/export/stix`, `/api/misp/*` | STIX/MISP export |
| `credentials.py` | `/api/credentials/*`, `/api/investigations/*/credentials/*` | Credential intelligence |
| `settings.py` | `/api/settings/*` | Service catalog, API key management, mode switching |
| `tradecraft.py` | `/api/tradecraft/*` | ACH, Admiralty scale, IC confidence, conclusions |
| `monitoring.py` | `/api/monitoring/watchlist/*`, `/api/monitoring/alerts/*` | Watchlist + alerts |

**Intelligence Modules:**
- `investigation_orchestrator.py` — 7-stage investigation workflow
- `mcp_clients.py` — MCP server HTTP client wrapper
- `intelligence_correlation.py` — Entity extraction and correlation engine (optional)
- `advanced_analysis.py` — MITRE ATT&CK mapping, risk scoring (optional)
- `expanded_data_sources.py` — Multi-source intelligence collectors (optional)
- `analytic_tradecraft.py` — NATO/Admiralty scale, ACH matrix, IC confidence levels
- `alert_engine.py` — Watchlist entries, infrastructure snapshots, diff engine
- `credential_intel_service.py` — HIBP, Dehashed, Hudson Rock, paste site orchestration
- `nlp_pipeline.py` — spaCy NLP, entity extraction, text classification
- `stix_export.py` — STIX 2.1 bundle generation, MISP event export

**Supporting Services:**
- `service_config.py` — 19-service catalog with tier classification (free/freemium/paid)
- `monitoring_scheduler.py` — Background daemon thread for continuous infra monitoring
- `professional_report_generator.py` — Professional PDF reports
- `compliance_framework.py` — GDPR/CCPA/HIPAA/SOX compliance engine
- `demo_data.py` — Demo mode data provider
- `observability.py` — OpenTelemetry instrumentation (aiohttp optional on Python 3.11)
- `problem_json.py` — RFC 7807 error responses

### Frontend (`frontend/`) — Modern TypeScript, 484 tests

**Pages (`src/pages/`) — all routed in App.tsx:**
- `Login.tsx` → `/login`
- `Dashboard.tsx` → `/dashboard`
- `Investigations.tsx` → `/investigations` (also `/investigations/active|history|saved`)
- `NewInvestigation.tsx` → `/investigations/new`
- `InvestigationDetail.tsx` → `/investigations/:id`
- `GraphIntelligence.tsx` → `/investigations/:id/graph`
- `ThreatAnalysis.tsx` → `/investigations/:id/threats`
- `AnalyticWorkbench.tsx` → `/investigations/:id/workbench`
- `Reports.tsx` → `/reports`
- `Monitoring.tsx` → `/monitoring`
- `CredentialIntelligence.tsx` → `/credentials`
- `ThreatIntelligence.tsx` → `/threat-intelligence`
- `CompliancePage.tsx` → `/compliance`
- `TeamPage.tsx` → `/team`
- `DataSourcesPage.tsx` → `/data-sources`
- `Settings.tsx` → `/settings`

**Component Library:**
- `src/components/common/` — Button, Card, Modal, FormField, StatusIndicator, Loading, Toast
- `src/components/layout/` — Header, Sidebar, Layout wrapper
- `src/components/dashboard/` — MITREDashboard, ExecutiveSummary, AnomalyPanel, RiskCommandCenter
- `src/components/visualizations/` — LineChart, BarChart, PieChart, NetworkGraph, Heatmap, etc.
- `src/components/a11y/` — SkipLinks, VisuallyHidden, ErrorBoundary, FocusRing
- `src/hooks/` — useKeyboardNavigation, useFocusTrap, useAnnounce, useMediaQuery
- `src/utils/` — `theme.ts` (cyberColors, glassmorphism, designTokens), validation.ts, a11y.ts

### MCP Servers (`mcp-servers/`)

| Server | Port | Purpose |
|--------|------|---------|
| `infrastructure-advanced` | 8021 | DNS, WHOIS, SSL certificates, port scanning |
| `threat-aggregator` | 8020 | VirusTotal, Shodan, AbuseIPDB, OTX |
| `ai-analyzer` | 8050 | GPT-4 analysis and threat profiling |
| `social-media-enhanced` | 8010 | Social intelligence gathering |
| `financial-enhanced` | 8040 | SEC filings, financial intelligence |
| `credential-intel` | 8030 | HIBP, Dehashed, Hudson Rock, paste monitoring |

## Development Commands

### Running the Platform
```bash
./start.sh demo              # Demo mode with sample data
./start.sh local             # With .env API keys
docker compose -f docker-compose.demo.yml up -d  # Manual
```

### Backend Development
```bash
cd simple-backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python app.py                # http://localhost:5001
pytest tests/ -v             # Run all tests
pytest tests/unit/ -v        # Unit tests only (500+)
```

### Kubernetes Deployment
```bash
./start.sh k8s               # Auto-deploy
# Or manually:
kubectl create namespace osint-platform
kubectl apply -f k8s/postgresql-deployment.yaml
kubectl apply -f k8s/simple-backend-deployment.yaml
kubectl apply -f k8s/simple-frontend-deployment.yaml
```

## Key API Endpoints

```
# Auth
POST /api/auth/login                              # Login → {access_token}
GET  /api/auth/me                                 # Current user info

# Investigations
GET  /api/investigations                          # List investigations
POST /api/investigations                          # Create investigation
GET  /api/investigations/{id}                     # Get investigation
POST /api/investigations/{id}/report              # Generate report
GET  /api/investigations/{id}/correlation         # Entity correlation
GET  /api/investigations/{id}/analysis/advanced   # MITRE mapping & risk scoring

# Analytic Tradecraft (IC Standards)
GET  /api/tradecraft/reference/admiralty          # NATO/Admiralty scale reference
GET  /api/tradecraft/investigations/{id}/items    # Intelligence items (Admiralty-rated)
GET  /api/tradecraft/investigations/{id}/ach      # ACH matrix
POST /api/tradecraft/investigations/{id}/hypotheses  # Add hypothesis
GET  /api/tradecraft/investigations/{id}/conclusions # Conclusions with IC language

# Monitoring & Alerting
GET  /api/monitoring/watchlist                    # List watchlist entries
POST /api/monitoring/watchlist                    # Add watchlist entry
GET  /api/monitoring/alerts                       # List alerts
POST /api/monitoring/alerts/{id}/acknowledge      # Acknowledge alert

# Credential Intelligence
GET  /api/credentials/status                      # Source availability
POST /api/credentials/check/email                 # Email exposure check
POST /api/credentials/check/domain                # Domain exposure check
POST /api/credentials/check/password              # k-anonymity password check
GET  /api/investigations/{id}/credentials/exposure # Investigation credential exposure

# Service Configuration
GET  /api/settings/services                       # Service catalog with status
POST /api/settings/services/{id}/key              # Save API key
POST /api/settings/services/{id}/test             # Test API key live
GET  /api/settings/mode                           # Demo vs Live mode

# Graph Intelligence
GET  /api/graph/status                            # Graph module status
POST /api/investigations/{id}/graph/sync          # Sync investigation to graph
POST /api/investigations/{id}/graph/analyze       # Full graph analysis
POST /api/investigations/{id}/graph/blast-radius  # Compromise impact analysis
POST /api/graph/centrality                        # Centrality metrics
POST /api/graph/communities                       # Community detection

# NLP & STIX
POST /api/nlp/extract                             # Extract entities from text
POST /api/investigations/{id}/export/stix         # Export as STIX 2.1 bundle
```

## Environment Variables

```bash
# Required
JWT_SECRET_KEY=your-secret
APP_DATA_DIR=/app/data        # Where tradecraft/monitoring/settings JSON files are stored

# Database (auto-configured in Docker)
POSTGRES_HOST=postgresql
POSTGRES_DB=osint_audit

# Mode
PLATFORM_MODE=demo            # "demo" or "live"
DEMO_MODE=true

# Optional API keys (configure via /settings UI or .env)
OPENAI_API_KEY=your-key
VIRUSTOTAL_API_KEY=your-key
SHODAN_API_KEY=your-key
ABUSEIPDB_API_KEY=your-key
HIBP_API_KEY=your-key
DEHASHED_API_KEY=your-key
```

## Testing

```bash
# Backend unit tests (500+)
cd simple-backend
pytest tests/unit/ -v
pytest tests/unit/ --cov --cov-report=term-missing

# Frontend tests (484 tests)
cd frontend
npm test                         # Run all tests
npm test -- --coverage           # With coverage
npx tsc --noEmit                 # TypeScript check
```

### CI Test Exclusions
A small number of tests require live infrastructure and are deselected in CI:
- Tests needing live Postgres/Redis: `test_health_ready_endpoint`, `test_ready_endpoint`, `test_create_investigation`, `test_configure_service`
- Tests with async mock incompatibility: `test_gather_intelligence_with_mocked_apis`
- Tests deleting env vars without restore: `test_missing_required_secrets`

All other unit tests (500+) run and pass in CI on Python 3.10 and 3.11.

## Graph Intelligence Engine

Palantir-style graph analytics. Located in `simple-backend/graph_intelligence/`.

- **models.py** — 35+ entity types, 45+ relationship types
- **neo4j_client.py** — Neo4j client with mock fallback for development
- **algorithms/centrality.py** — PageRank, betweenness, closeness, eigenvector
- **algorithms/paths.py** — Shortest path, all paths, reachability, pivot finding
- **algorithms/community.py** — Louvain, label propagation, k-core
- **algorithms/similarity.py** — Jaccard, Adamic-Adar, cosine, SimRank
- **algorithms/anomaly.py** — Degree, clustering, bridge, hub/authority anomalies
- **algorithms/influence.py** — Independent cascade, SIR/SIS, blast radius

See `docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md` for full design.

## Documentation

- `README.md` — Main documentation and feature overview
- `QUICKSTART.md` — 5-minute getting started guide
- `API_REFERENCE.md` — Complete API endpoint reference
- `ARCHITECTURE_OVERVIEW.md` — System architecture
- `DEPLOYMENT_GUIDE.md` — Production Kubernetes deployment
- `CONFIGURATION.md` — In-app service configuration and API keys
- `CHANGELOG.md` — Version history (keep updated when adding features)
- `docs/` — Extended docs (graph architecture, external secrets, roadmaps)
