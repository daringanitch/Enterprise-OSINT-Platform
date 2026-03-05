# Enterprise OSINT Platform

A production-ready Open Source Intelligence (OSINT) investigation platform for enterprise security teams, threat hunters, and intelligence analysts.

## Quick Start

```bash
./start.sh demo
```

Open http://localhost:8080 and login with `admin` / `admin123`

That's it! See [QUICKSTART.md](QUICKSTART.md) for more options.

> **Note:** The one-command demo uses the legacy `simple-frontend` (a single-page HTML app) which
> exposes only a small slice of the platform. For the full analyst experience — MITRE ATT&CK
> matrix, graph intelligence, credential exposure, threat actor dossiers, live collaboration,
> and 16 dedicated pages — deploy the **React frontend** via Kubernetes or Docker Compose.
> [See the Demo vs. Full Platform comparison below.](#demo-vs-full-platform)

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

### Analyst Collaboration & Productivity
- **Live Collaboration**: Socket.IO investigation rooms — real-time analyst presence, live annotation feed with entity tagging, cursor broadcasting, and 20-second heartbeat. Multiple analysts can annotate the same investigation simultaneously and see each other's notes as they are written.
- **Command Palette (⌘K)**: Keyboard-first launcher giving instant access to any page, investigation, or action. Paste an IOC directly into the palette to trigger fan-out enrichment without navigating to a new page.
- **Saved Searches with Alerting**: Save filter combinations (status, priority, risk level, free text) and receive Toast notifications when new investigations match since your last visit.
- **Investigation Kanban View**: Visual 5-column operational board (New → Active → Analysis → Reporting → Closed) as an alternative to the list view. Toggle is persisted per-user.
- **Indicator Freshness/Decay Badges**: Each IOC displays a color-coded age tier (fresh / recent / aging / stale / expired) with a decay warning when ownership or sinkholing may have changed.

### Enrichment & Analysis
- **Unified IOC Enrichment ("Investigate This")**: Single command fans out to all 5 MCP intelligence servers in parallel and streams results back to the UI as a live timeline via Server-Sent Events. See each source resolve in real time with findings, confidence, and risk scores.
- **Interactive MITRE ATT&CK Matrix**: Full 14-tactic × N-technique grid with evidence heat-map and coverage modes. Click to select techniques and filter findings. One-click export to ATT&CK Navigator layer JSON compatible with `navigator.attack.mitre.org`.
- **Confidence Scoring & Evidence Chain**: Every finding can expose a visual `source → finding → inference → conclusion` chain. Chain confidence is the geometric mean of all node scores (a weak link degrades the whole chain). Designed for defensible, auditable intelligence reports.
- **Entity Hover Preview Cards**: Hovering any IP, domain, email, or hash anywhere in the UI shows a rich popover (risk score, linked investigations, last seen, top findings) without navigating away.

### Enterprise Features
- **Professional PDF Reports**: Executive and technical summaries
- **Compliance Framework**: GDPR/CCPA assessment
- **Audit Trail**: Complete investigation history
- **Role-Based Access**: Admin, analyst, viewer roles
- **Demo Mode**: Full functionality without API keys

### Frontend Component Library
- **Design System**: Centralized theme with design tokens
- **Reusable Components**: Button, Card, Modal, FormField, StatusIndicator, Loading, Toast, EntityChip, FreshnessIndicator, EvidenceChain
- **Layout Components**: Header, Sidebar, responsive Layout wrapper with global Command Palette
- **Collaboration Components**: PresenceBar (analyst avatars + live status), AnnotationPanel (real-time shared notes)
- **Enrichment Components**: EnrichmentPanel (live SSE progress timeline)
- **Visualization Components**: Charts (Line, Bar, Pie, Area), RiskGauge, Timeline, NetworkGraph, Heatmap, ThreatMatrix, MitreMatrix (interactive + Navigator export), DataTable
- **Accessibility**: WCAG 2.1 compliant with keyboard navigation, focus management, screen reader support
- **484+ Component Tests**: Comprehensive test coverage

## Demo vs. Full Platform

The quick-start demo (`./start.sh demo`) is a **proof-of-concept** designed to let you kick the
tyres in under five minutes — no API keys, no config files, no infrastructure required. It
serves the **`simple-frontend`** (a legacy single-page HTML/JS app) backed by the full Flask
API, but the UI only wires up a handful of endpoints and has no navigation beyond dashboards and
basic investigation management.

The **full platform** ships an entirely separate, production-grade React frontend with 16
dedicated pages, a component design system, and deep integrations into every backend capability.

### What the Demo Gives You

| Component | Demo (`simple-frontend`) |
|-----------|--------------------------|
| UI technology | Vanilla HTML / CSS / JavaScript (single `index.html`) |
| Navigation | Dashboard, Investigations list, basic investigation detail |
| Investigations | Create, view status, view basic findings |
| Reports | View/download PDF reports |
| API coverage | ~10 of 160+ endpoints wired to the UI |
| Real-time features | None |
| Graph intelligence | Not visible in UI (available via API) |
| MITRE ATT&CK | Not visible in UI (available via API) |
| Compliance | Not visible in UI (available via API) |
| Credential intelligence | Not visible in UI (available via API) |
| Threat actor dossiers | Not visible in UI (available via API) |
| Collaboration | Not visible in UI (available via API) |
| Monitoring / watchlists | Not visible in UI (available via API) |

The demo is intentionally minimal so first-time users aren't overwhelmed. All 160+ API endpoints
are fully operational in demo mode — you can call them directly with `curl` or any HTTP client.

### What the Full Platform (React Frontend + Kubernetes) Gives You

Deploying the React frontend — either via `docker compose` (see the `frontend/` service) or
`kubectl apply -f k8s/` — unlocks all 16 pages and the complete analyst workflow:

| Page | Route | What you can do |
|------|-------|-----------------|
| **Dashboard** | `/dashboard` | Real-time KPI widgets, recent investigations, risk heatmap, alert feed, API health status |
| **Investigations** | `/investigations` | Full list with search/filter bar, saved searches with Toast alerts, **Kanban view** (5-column operational board), indicator freshness badges |
| **New Investigation** | `/investigations/new` | 6 pre-built analyst templates (APT attribution, ransomware, phishing, M&A due diligence, insider threat, vulnerability exposure) |
| **Investigation Detail** | `/investigations/:id` | 7-stage workflow progress, entity timeline, pivot suggestions, cross-investigation correlation, live analyst collaboration (presence + annotations) |
| **Graph Intelligence** | `/investigations/:id/graph` | Palantir-style interactive network graph — 35+ entity types, 45+ relationship types, PageRank, betweenness centrality, community detection, blast radius / compromise impact analysis |
| **Threat Analysis** | `/investigations/:id/threats` | MITRE ATT&CK technique evidence with heatmap overlay, one-click export to ATT&CK Navigator layer JSON |
| **Analytic Workbench** | `/investigations/:id/workbench` | NATO Admiralty rating scale, ACH (Analysis of Competing Hypotheses) matrix, IC-standard confidence levels, devil's advocate workflow |
| **Reports** | `/reports` | PDF report library, executive vs. technical summaries, STIX 2.1 bundle export, scheduled report runs |
| **Threat Intelligence** | `/threat-intelligence` | 26-actor threat actor dossier library, TTP overlap scoring (MITRE ATT&CK), sector and technique filtering, entity hover preview cards |
| **Compliance** | `/compliance` | GDPR/CCPA/HIPAA assessment dashboards, evidence mapping, remediation tracking |
| **Credential Intelligence** | `/credentials` | HIBP / Dehashed / Hudson Rock breach lookup, paste site monitoring, k-anonymity password checks |
| **Monitoring** | `/monitoring` | Real-time watchlist manager, snapshot diffing, configurable check intervals, alert history |
| **Team** | `/team` | User management, role assignments (admin / analyst / viewer), audit trail |
| **Data Sources** | `/data-sources` | MCP server health and configuration — Infrastructure (DNS/WHOIS/certs), Threat (VT/Shodan/AbuseIPDB), Social, Financial (SEC), AI Analyzer |
| **Settings** | `/settings` | API key management, notification preferences, theme, platform configuration |

#### How to Navigate the UI

The full React frontend organizes its 16 pages across three navigation mechanisms:

**1. Left Sidebar — always visible**

The sidebar is split into two labelled sections. Clicking a top-level item navigates directly;
"Investigations" expands in-place to reveal three sub-items.

```
MAIN
  Dashboard
  Investigations
    ├─ Active
    ├─ History
    └─ Saved
  Reports
  Threat Intelligence
  Compliance

ADMINISTRATION
  Team
  Data Sources
  Monitoring
  Credentials
  Settings
```

The sidebar collapses to icon-only mode (64 px) — hover any icon to see its label as a tooltip.

**2. Investigation-Scoped Pages — reached from inside an investigation**

Four pages live inside a specific investigation. Open any investigation from the Investigations
list, then use the tabs or navigation links within the Investigation Detail view:

| Page | How to reach it |
|------|-----------------|
| Investigation Detail | Click any investigation in the list |
| Graph Intelligence | "Graph" tab inside an open investigation |
| Threat Analysis | "Threats" tab inside an open investigation |
| Analytic Workbench | "Workbench" tab inside an open investigation |

**3. New Investigation — triggered from the Investigations list**

Click the **+ New Investigation** button on the Investigations list page to reach the template
picker and form at `/investigations/new`.

**4. Command Palette (⌘K / Ctrl+K) — keyboard shortcut from anywhere**

Press ⌘K (Mac) or Ctrl+K (Windows/Linux) at any time to open the Command Palette. Type to jump
to any sidebar page, open a recent investigation by name, or paste an IOC directly to trigger
fan-out enrichment — all without taking your hands off the keyboard.

---

#### Cross-Cutting Features (Available on Every Page)

- **Command Palette (⌘K / Ctrl+K)**: Keyboard-first launcher — navigate to any page, open any
  investigation, or paste an IOC directly to trigger immediate fan-out enrichment without leaving
  your current view.
- **Live Collaboration**: Socket.IO investigation rooms with real-time analyst presence (avatars +
  status), live annotation feed with entity tagging, and cursor broadcasting. Multiple analysts
  can annotate the same investigation simultaneously.
- **Unified IOC Enrichment ("Investigate This")**: Single command fans out to all 5 MCP
  intelligence servers in parallel and streams results back via Server-Sent Events (SSE) as a
  live timeline — see each source resolve in real time with findings, confidence, and risk scores.
- **Entity Hover Preview Cards**: Hovering any IP, domain, email address, or hash anywhere in
  the UI shows a rich popover (risk score, linked investigations, last seen, top findings) without
  navigating away.
- **Indicator Freshness / Decay Badges**: Every IOC displays a color-coded age tier (🟢 fresh
  < 7 d / 🔵 recent < 30 d / 🟠 aging < 90 d / 🔴 stale < 180 d / ⚫ expired > 180 d) with
  an automatic warning when IP ownership or domain sinkholing may have changed.
- **Evidence Chain Viewer**: Each finding can expose a visual `source → finding → inference →
  conclusion` confidence chain. Chain confidence is the geometric mean of all node scores —
  a weak link degrades the whole chain — designed for auditable, defensible intelligence.

### Accessing the Full API in Demo Mode

Even without the React frontend, every endpoint is reachable directly. The demo backend starts
on `http://localhost:5001`. Get a token and start exploring:

```bash
# 1. Login
TOKEN=$(curl -s -X POST http://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# 2. Create an investigation
curl -s -X POST http://localhost:5001/api/investigations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target":"evil.example.com","investigation_type":"comprehensive"}' | python3 -m json.tool

# 3. Match threat actors by TTP
curl -s -X POST http://localhost:5001/api/threat-actors/match \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"techniques":["T1566.001","T1071.001"]}' | python3 -m json.tool

# 4. Apply an investigation template
curl -s -X POST http://localhost:5001/api/templates/apt_attribution/apply \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target":"evil.example.com","target_type":"domain"}' | python3 -m json.tool

# 5. Compliance frameworks
curl -s http://localhost:5001/api/compliance/frameworks \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

See [API_REFERENCE.md](API_REFERENCE.md) for the complete endpoint catalogue.

---

## Deployment Options

### Option 1: Docker Compose — Demo (no config required)

Uses `docker-compose.demo.yml` with hardcoded demo credentials. No `.env` file
needed. **Do not use these credentials in production.**

```bash
# Start everything
make demo
# — or —
docker compose -f docker-compose.demo.yml up -d

# Start worker only
make demo-worker
# — or —
docker compose -f docker-compose.demo.yml up -d worker

# Tail logs
make demo-logs

# Stop + remove volumes
make demo-down
```

Access: **http://localhost:8080** — Login: `admin` / `admin123`

> **Common mistake:** Running `docker compose up -d` (without `-f docker-compose.demo.yml`)
> requires a `.env` file with real `POSTGRES_PASSWORD`, `JWT_SECRET_KEY`, `VAULT_MASTER_KEY`,
> and `VAULT_TOKEN`. Copy `.env.template` → `.env` and fill in values, or use the demo
> compose file above.

### Option 2: Docker Compose — Production

```bash
cp .env.template .env          # fill in POSTGRES_PASSWORD, JWT_SECRET_KEY, etc.
docker compose up -d           # starts backend, worker, frontend, postgres, redis, vault
```

See `.env.template` for vault setup instructions (one-time init required).

### Option 3: Kubernetes

```bash
make setup && make deploy && make port-forward
# — or —
./start.sh k8s
```

## Project Structure

```
Enterprise-OSINT-Platform/
├── simple-backend/              # Flask REST API
│   ├── app.py                   # Main application (60+ endpoints)
│   ├── blueprints/              # 24 Flask Blueprint modules
│   │   ├── auth.py, health.py, admin.py
│   │   ├── investigations.py, reports.py, compliance.py
│   │   ├── tradecraft.py, monitoring.py, credentials.py
│   │   ├── pivots.py, correlations.py, threat_actors.py
│   │   ├── templates.py, graph.py, settings.py
│   │   ├── entities.py, searches.py  # Entity lookup + saved searches
│   │   ├── collaboration.py   # Socket.IO presence + annotations
│   │   └── enrichment.py      # Unified IOC fan-out (SSE)
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
│   │   ├── common/              # Button, Card, Modal, EntityChip, FreshnessIndicator, CommandPalette
│   │   ├── layout/              # Header, Sidebar, Layout (+ global ⌘K)
│   │   ├── collaboration/       # PresenceBar, AnnotationPanel
│   │   ├── enrichment/          # EnrichmentPanel (SSE streaming)
│   │   ├── analysis/            # EvidenceChain
│   │   ├── investigations/      # KanbanBoard, SearchBar
│   │   ├── dashboard/           # Dashboard components
│   │   └── visualizations/      # Charts, NetworkGraph, MitreMatrix, ThreatMatrix, ...
│   ├── src/hooks/               # useCollaboration, useCommandPalette, useSavedSearches, ...
│   ├── src/utils/               # freshness.ts, theme, validation, a11y utilities
│   └── src/__tests__/           # Frontend tests (484+ tests)
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
- **Real-Time**: Flask-SocketIO + Socket.IO client (analyst collaboration)
- **Testing**: Jest, React Testing Library, pytest (936+ total tests — 652 backend passing, 5 require live infra)
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
