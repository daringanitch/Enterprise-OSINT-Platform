# CLAUDE.md

Guidance for Claude Code when working with this repository.

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
├── simple-backend/          # Flask REST API (Python 3.11+)
├── simple-frontend/         # Legacy React SPA (HTML/JS)
├── frontend/                # Modern React Frontend (TypeScript)
│   ├── src/components/      # Reusable UI components
│   ├── src/hooks/           # Custom React hooks
│   ├── src/utils/           # Theme, validation, a11y utilities
│   └── src/__tests__/       # Frontend tests (350+ tests)
├── mcp-servers/             # Intelligence microservices (FastAPI)
├── k8s/                     # Kubernetes manifests
├── scripts/                 # Utility scripts (deploy/, dev/, maintenance/)
├── docs/                    # Extended documentation
├── start.sh                 # One-command setup
└── docker-compose.demo.yml  # Demo deployment
```

## Core Components

### Backend (`simple-backend/`)
- `app.py` - Flask REST API with 60+ endpoints, JWT auth
- `models.py` - SQLAlchemy ORM for PostgreSQL
- `investigation_orchestrator.py` - 7-stage investigation workflow
- `mcp_clients.py` - MCP server communication
- `professional_report_generator.py` - PDF reports
- `compliance_framework.py` - GDPR/CCPA validation
- `demo_data.py` - Demo mode data provider
- `intelligence_correlation.py` - Entity correlation engine
- `advanced_analysis.py` - MITRE ATT&CK mapping, risk scoring
- `expanded_data_sources.py` - 6 intelligence source collectors

### Frontend (`frontend/`) - Modern TypeScript
- `src/components/common/` - Button, Card, Modal, FormField, StatusIndicator, Loading, Toast
- `src/components/layout/` - Header, Sidebar, Layout wrapper
- `src/components/a11y/` - SkipLinks, VisuallyHidden, ErrorBoundary, FocusRing
- `src/hooks/` - useKeyboardNavigation, useFocusTrap, useAnnounce, useMediaQuery
- `src/utils/` - theme.ts (design system), validation.ts, a11y.ts

### Legacy Frontend (`simple-frontend/`)
- `index.html` - React SPA with Material-UI
- `nginx.conf` / `nginx-demo.conf` - Nginx configuration

### MCP Servers (`mcp-servers/`)
| Server | Port | Purpose |
|--------|------|---------|
| `infrastructure-advanced` | 8021 | DNS, WHOIS, SSL, ports |
| `threat-aggregator` | 8020 | VirusTotal, Shodan, AbuseIPDB |
| `ai-analyzer` | 8050 | GPT-4 analysis |
| `social-media-enhanced` | 8010 | Social intelligence |
| `financial-enhanced` | 8040 | SEC, financial data |

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
pytest tests/ -v             # Run tests
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
POST /api/auth/login                        # Login (admin/admin123)
GET  /api/investigations                    # List investigations
POST /api/investigations                    # Create investigation
GET  /api/investigations/{id}               # Get investigation
POST /api/investigations/{id}/report        # Generate report
GET  /api/investigations/{id}/correlation   # Entity correlation analysis
GET  /api/investigations/{id}/analysis/advanced  # MITRE mapping & risk scoring
GET  /api/system/status                     # Platform health
GET  /api/mcp/servers                       # MCP server status
```

## Environment Variables

```bash
# Required
JWT_SECRET_KEY=your-secret

# Database (auto-configured in Docker)
POSTGRES_HOST=postgresql
POSTGRES_DB=osint_audit

# Optional API keys
OPENAI_API_KEY=your-key
VIRUSTOTAL_API_KEY=your-key
SHODAN_API_KEY=your-key
```

## Testing

```bash
# Backend tests (220+ tests)
cd simple-backend
pytest tests/unit/ -v            # Unit tests
pytest tests/integration/ -v     # Integration tests
pytest tests/ --cov --cov-report=term-missing

# Frontend tests (350+ tests)
cd frontend
npm test                         # Run all tests
npm test -- --coverage           # With coverage
```

## Frontend Development

```bash
cd frontend
npm install                      # Install dependencies
npm start                        # Development server
npm run build                    # Production build
npm test                         # Run tests
```

### Component Library
- **Design System**: `src/utils/theme.ts` - Color tokens, typography, spacing
- **Common Components**: Button, Card, Modal, FormField, StatusIndicator, Loading, Toast
- **Layout Components**: Header, Sidebar, Layout, PageWrapper
- **Accessibility**: WCAG 2.1 compliant with keyboard navigation, screen reader support

## Scripts Organization

```
scripts/
├── deploy/       # build-images.sh, deploy-demo-production-mode.sh
├── dev/          # test-endpoints.sh, test-auth-endpoints.py
├── maintenance/  # validate-config.py, fix-database-schema.py
└── legacy/       # Deprecated scripts (reference only)
```

## Graph Intelligence Engine (In Progress)

Palantir-style graph analytics for OSINT investigations. Located in `simple-backend/graph_intelligence/`.

### Completed Components
- **models.py** - 35+ entity types, 45+ relationship types, graph data structures
- **neo4j_client.py** - Neo4j database client with mock fallback for development
- **algorithms/centrality.py** - PageRank, betweenness, closeness, eigenvector, harmonic, katz
- **algorithms/paths.py** - Shortest path, all paths, reachability, pivot finding
- **algorithms/community.py** - Louvain, label propagation, k-core, clustering coefficient
- **algorithms/similarity.py** - Jaccard, Adamic-Adar, cosine, SimRank, infrastructure/threat actor similarity
- **algorithms/anomaly.py** - Degree, clustering, bridge, hub/authority, star pattern, attribute anomalies
- **algorithms/influence.py** - Independent cascade, linear threshold, SIR/SIS epidemic, blast radius
- **api.py** - Flask Blueprint with REST endpoints for all graph operations
- **sync.py** - Extract entities from investigations, build relationships, sync to graph

### Architecture Documentation
See `docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md` for full design specifications.

## Documentation

- `README.md` - Main documentation
- `QUICKSTART.md` - 5-minute getting started
- `API_REFERENCE.md` - Complete API docs
- `ARCHITECTURE_OVERVIEW.md` - System architecture
- `DEPLOYMENT_GUIDE.md` - Production deployment
- `CONFIGURATION.md` - Environment configuration
- `docs/` - Extended docs (roadmaps, advanced topics)
