# Enterprise OSINT Platform

A production-ready Open Source Intelligence (OSINT) investigation platform for enterprise security teams, threat hunters, and intelligence analysts.

## Quick Start

```bash
./start.sh demo
```

Open http://localhost:8080 and login with `admin` / `admin123`

That's it! See [QUICKSTART.md](QUICKSTART.md) for more options.

## Platform Overview

```
┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────────┐
│   React Frontend    │────▶│   Flask Backend     │────▶│    Enhanced MCP Servers │
│   (Material-UI)     │     │   (REST API)        │     │   (FastAPI)             │
└─────────────────────┘     └─────────────────────┘     └─────────────────────────┘
                                      │                              │
                                      ▼                              ▼
                            ┌─────────────────────┐     ┌─────────────────────────┐
                            │    PostgreSQL       │     │    External APIs        │
                            │  (Audit Database)   │     │  (VirusTotal, Shodan,   │
                            └─────────────────────┘     │   OpenAI, etc)          │
                                                        └─────────────────────────┘
```

## Features

### Intelligence Gathering
- **Infrastructure Analysis**: DNS, WHOIS, SSL certificates, subdomains
- **Threat Intelligence**: VirusTotal, Shodan, AbuseIPDB integration
- **Social Media Intelligence**: Multi-platform profile analysis
- **AI-Enhanced Analysis**: GPT-4 powered threat assessment
- **Financial Intelligence**: SEC filings, company research

### Advanced Analysis
- **Intelligence Correlation**: Cross-source entity extraction and relationship mapping
- **MITRE ATT&CK Mapping**: Automated technique identification with 14 tactics
- **Risk Scoring Engine**: 6-category weighted scoring with trend analysis
- **Timeline Reconstruction**: Automated event correlation and sequencing
- **Graph Intelligence**: Neo4j-based relationship analysis with PageRank, community detection, and blast radius analysis

### Intelligence Operations
- **Pivot Suggestions**: Composite-scored next-pivot recommendations (threat flag, corroboration, centrality, recency, unresolved)
- **Threat Actor Dossiers**: 26-actor library with MITRE ATT&CK mappings, TTP overlap scoring, sector and technique filtering
- **Cross-Investigation Correlation**: Shared indicator detection across all investigations (domains, IPs, emails, certs, ASNs)
- **Investigation Templates**: 6 analyst-ready templates (APT attribution, ransomware, phishing, M&A due diligence, insider threat, vulnerability exposure)
- **Analytic Tradecraft**: NATO Admiralty scale, ACH matrix, IC-standard confidence levels, devil's advocate workflow
- **Credential Intelligence**: HIBP, Dehashed, Hudson Rock, paste monitoring with k-anonymity password checks
- **Real-Time Monitoring**: Watchlist alerting with snapshot diffing, configurable check intervals

### Enterprise Features
- **Professional PDF Reports**: Executive and technical summaries
- **Compliance Framework**: GDPR/CCPA assessment
- **Audit Trail**: Complete investigation history
- **Role-Based Access**: Admin, analyst, viewer roles
- **Demo Mode**: Full functionality without API keys

### Frontend Component Library
- **Design System**: Centralized theme with design tokens
- **Reusable Components**: Button, Card, Modal, FormField, StatusIndicator, Loading, Toast
- **Layout Components**: Header, Sidebar, responsive Layout wrapper
- **Visualization Components**: Charts (Line, Bar, Pie, Area), RiskGauge, Timeline, NetworkGraph, Heatmap, ThreatMatrix, DataTable
- **Accessibility**: WCAG 2.1 compliant with keyboard navigation, focus management, screen reader support
- **484 Component Tests**: Comprehensive test coverage

## Deployment Options

### Option 1: Docker Compose (Recommended for Evaluation)

```bash
./start.sh demo    # Demo mode - no API keys needed
./start.sh local   # Local dev with optional API keys
```

### Option 2: Kubernetes

```bash
./start.sh k8s     # Deploy to Kubernetes cluster
```

### Option 3: Manual Docker Compose

```bash
docker compose -f docker-compose.demo.yml up -d
```

## Project Structure

```
Enterprise-OSINT-Platform/
├── simple-backend/              # Flask REST API
│   ├── app.py                   # Main application (60+ endpoints)
│   ├── blueprints/              # 20 Flask Blueprint modules
│   │   ├── auth.py, health.py, admin.py
│   │   ├── investigations.py, reports.py, compliance.py
│   │   ├── tradecraft.py, monitoring.py, credentials.py
│   │   ├── pivots.py, correlations.py, threat_actors.py
│   │   └── templates.py, graph.py, settings.py, ...
│   ├── pivot_engine.py          # Next-pivot recommendation engine
│   ├── threat_actor_library.py  # 26-actor MITRE ATT&CK dossier library
│   ├── cross_investigation_correlator.py  # Shared indicator detection
│   ├── investigation_templates.py # 6 analyst-ready templates
│   ├── analytic_tradecraft.py   # Admiralty scale, ACH, IC confidence
│   ├── credential_intel_service.py # HIBP, Dehashed, Hudson Rock
│   ├── graph_intelligence/      # Palantir-style graph analytics
│   │   ├── algorithms/          # Centrality, paths, community, etc.
│   │   └── api.py               # Graph REST endpoints
│   ├── models.py                # Database models
│   ├── intelligence_correlation.py  # Entity correlation engine
│   ├── advanced_analysis.py     # MITRE mapping, risk scoring
│   └── tests/                   # Backend test suite (220+ tests)
├── frontend/                    # React Frontend (TypeScript)
│   ├── src/components/          # UI components
│   │   ├── common/              # Button, Card, Modal, etc.
│   │   ├── layout/              # Header, Sidebar, Layout
│   │   ├── dashboard/           # Dashboard components
│   │   └── visualizations/      # Charts, graphs, heatmaps
│   ├── src/hooks/               # Custom React hooks
│   ├── src/utils/               # Theme, validation, a11y utilities
│   └── src/__tests__/           # Frontend tests (484 tests)
├── simple-frontend/             # Legacy React SPA (index.html)
├── mcp-servers/                 # Intelligence microservices
│   ├── infrastructure-advanced/ # Port 8021
│   ├── threat-aggregator/       # Port 8020
│   ├── social-media-enhanced/   # Port 8010
│   ├── financial-enhanced/      # Port 8040
│   ├── ai-analyzer/             # Port 8050
│   └── credential-intel/        # Port 8030
├── k8s/                         # Kubernetes manifests (54 files)
├── scripts/                     # Organized utility scripts
├── start.sh                     # One-command setup
└── docker-compose.demo.yml      # Demo deployment
```

## API Quick Reference

```bash
# Login
curl -X POST http://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Start Investigation
curl -X POST http://localhost:5001/api/investigations \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "investigation_type": "comprehensive"}'

# Get Correlation Analysis
curl http://localhost:5001/api/investigations/{id}/correlation \
  -H "Authorization: Bearer YOUR_TOKEN"

# Get Advanced Analysis
curl http://localhost:5001/api/investigations/{id}/analysis/advanced \
  -H "Authorization: Bearer YOUR_TOKEN"

# Get Pivot Suggestions
curl http://localhost:5001/api/investigations/{id}/pivots \
  -H "Authorization: Bearer YOUR_TOKEN"

# Cross-Investigation Correlations
curl http://localhost:5001/api/correlations \
  -H "Authorization: Bearer YOUR_TOKEN"

# Match Threat Actors by TTPs
curl -X POST http://localhost:5001/api/threat-actors/match \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"techniques": ["T1566.001", "T1071.001"]}'

# Apply Investigation Template
curl -X POST http://localhost:5001/api/templates/apt_attribution/apply \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "evil.example.com", "target_type": "domain"}'
```

## Adding API Keys (Optional)

Create a `.env` file for external integrations:

```bash
OPENAI_API_KEY=your-key
VIRUSTOTAL_API_KEY=your-key
SHODAN_API_KEY=your-key
```

Then restart with `./start.sh local`

## Documentation

| Document | Description |
|----------|-------------|
| [QUICKSTART.md](QUICKSTART.md) | 5-minute getting started guide |
| [ARCHITECTURE_OVERVIEW.md](ARCHITECTURE_OVERVIEW.md) | System architecture details |
| [API_REFERENCE.md](API_REFERENCE.md) | Complete API documentation |
| [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) | Production deployment |
| [CONFIGURATION.md](CONFIGURATION.md) | Environment configuration |
| [CHANGELOG.md](CHANGELOG.md) | Version history and changes |
| [DEMO_SCRIPT.md](DEMO_SCRIPT.md) | "Operation SHATTERED PANE" 10-minute demo walkthrough |
| [docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md](docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md) | Graph engine design and algorithms |

## Technology Stack

- **Backend**: Flask, SQLAlchemy, PostgreSQL, Redis, Neo4j (optional)
- **Frontend**: React 18, TypeScript, Material-UI
- **Component Library**: Custom design system with 10+ reusable components
- **Testing**: Jest, React Testing Library, pytest (936 total tests — 871 passing, 5 require live infra)
- **MCP Servers**: FastAPI, aiohttp
- **Infrastructure**: Docker, Kubernetes, Prometheus, Grafana

## Commands Reference

```bash
./start.sh              # Interactive setup
./start.sh demo         # Start demo mode
./start.sh local        # Start with local config
./start.sh k8s          # Deploy to Kubernetes
./start.sh stop         # Stop all services
./start.sh status       # Check service health
./start.sh logs         # View logs
```

## Troubleshooting

### Container name conflict when switching modes

**Symptom:** `Error response from daemon: Conflict. The container name "/osint-backend" is already in use`

This happens when you switch between Demo mode and Local mode (or vice versa) without stopping the previous stack first. Both compose files create containers with the same names.

**Fix:** Remove the orphaned containers, then re-run `./start.sh`:

```bash
docker rm -f osint-backend osint-frontend
./start.sh
```

Or cleanly tear down the previous stack before switching:

```bash
# If coming from demo mode
docker compose -f docker-compose.demo.yml down

# If coming from local mode
docker compose down
```

### Backend container fails to start (`ModuleNotFoundError: No module named 'blueprints'`)

**Symptom:** `osint-backend` exits immediately; logs show `ModuleNotFoundError: No module named 'blueprints'`

Docker is running a stale image built before the `blueprints/` directory was added to the Dockerfile. Force a clean rebuild:

```bash
docker compose -f docker-compose.demo.yml build --no-cache osint-backend
docker compose -f docker-compose.demo.yml up -d --force-recreate osint-backend
```

### Vault authentication warnings on startup

**Symptom:** `ERROR:vault_client:Vault authentication failed: No Vault token available`

This is expected in demo and local development modes — Vault is not required and the backend falls back to environment variable secrets automatically. You can safely ignore this warning.

### No external API data (VirusTotal, Shodan, etc.)

**Symptom:** Intelligence gathering returns empty or mock results

API integrations require keys. Create a `.env` file in the project root:

```bash
cp .env.example .env   # if example exists, otherwise create manually
# Then add your keys:
OPENAI_API_KEY=your-key
VIRUSTOTAL_API_KEY=your-key
SHODAN_API_KEY=your-key
```

Then restart: `./start.sh local`

### Port already in use

**Symptom:** `bind: address already in use` on port 5001 or 8080

```bash
# Find what's using the port
lsof -i :5001
lsof -i :8080

# Stop the offending process, then restart
./start.sh stop && ./start.sh
```

### View logs for any service

```bash
docker compose logs -f osint-backend    # Backend API
docker compose logs -f osint-frontend   # Frontend
docker compose logs -f osint-postgresql # Database
docker compose logs -f osint-redis      # Cache
```

---

## Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/new-capability`
3. Commit changes: `git commit -m 'Add new OSINT capability'`
4. Push to branch: `git push origin feature/new-capability`
5. Submit pull request

## License

**Enterprise OSINT Platform License**

- **Individual Use**: Free for personal, educational, or research purposes
- **Commercial Use**: 3% revenue share on net profits

See [LICENSE](LICENSE) for complete terms.

---

**Enterprise OSINT Platform** - Professional open-source intelligence for modern security teams.
