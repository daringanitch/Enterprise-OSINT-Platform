# Changelog

All notable changes to the Enterprise OSINT Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Credential Intelligence & Exposure Monitoring
- **`mcp-servers/credential-intel/`** — FastAPI MCP server with four independent source clients:
  - `hibp_client.py`: Have I Been Pwned breaches + pastes (free, no key for password checks)
  - `dehashed_client.py`: Dehashed leaked credential search (API key required)
  - `hudson_rock_client.py`: Hudson Rock Cavalier infostealer victim database
  - `paste_monitor.py`: Paste site monitoring for credential dumps
- **`credential_intel_service.py`** — Orchestrator that fans out to all 4 sources, merges results, and computes a 0–100 risk score (→ none/low/medium/high/critical)
- **`blueprints/credentials.py`** — Flask REST blueprint:
  - `GET  /api/credentials/status` — source availability and API key status
  - `POST /api/credentials/check/email` — multi-source email exposure check
  - `POST /api/credentials/check/domain` — domain-wide credential exposure (all @domain accounts)
  - `POST /api/credentials/check/password` — k-anonymity HIBP password check (full password never sent)
  - `POST /api/credentials/analyze/passwords` — local password pattern and reuse analysis (no external calls)
  - `GET  /api/investigations/<id>/credentials/exposure` — auto-extracts emails/domains from investigation entities and runs exposure checks
- **`k8s/credential-intel-mcp.yaml`** — Kubernetes Deployment + Service manifest
- **`frontend/src/pages/CredentialIntelligence.tsx`** — Credential Intelligence UI (route `/credentials`):
  - Email tab: HIBP breach count, paste count, infostealer flag, plaintext password indicator with risk scoring
  - Domain tab: exposed email count, infostealer employee count, dehashed entries, paste count
  - Password tab: k-anonymity check with privacy explanation; shows pwned count
  - Source status panel: live availability indicators (HIBP, Dehashed, Hudson Rock, Paste)
  - Risk badges colour-coded critical/high/medium/low/none with progress bars
- Sidebar: added **Credentials** nav entry (ManageSearchIcon) between Monitoring and Settings

#### Analytic Tradecraft & Confidence Scoring (IC Standards)
- **`analytic_tradecraft.py`** — Full implementation of intelligence community structured analytic techniques:
  - NATO/Admiralty scale (A-F source reliability × 1-6 information credibility) with complete label/description reference data
  - IC-standard confidence levels (High/Moderate/Low) with ICD 203 controlled vocabulary and Sherman Kent Words of Estimative Probability scale
  - Analysis of Competing Hypotheses (ACH) matrix engine: evidence × hypothesis consistency ratings (C/I/N/NA) with Heuer diagnostic scoring
  - `AlternativeExplanation` model: forces analysts to document why alternatives were rejected, preventing confirmation bias
  - `DevilsAdvocacy` model: designated dissent workflow with lead analyst response tracking
  - `AnalyticConclusion` model: IC-statement generator ("We assess with high confidence that…"), completeness enforcer before finalisation
- **`blueprints/tradecraft.py`** — 20+ REST endpoints for all tradecraft workflows
- **`frontend/src/pages/AnalyticWorkbench.tsx`** — Analytic Workbench UI (route `/investigations/:id/workbench`):
  - Tab 1 Intelligence Items: Admiralty-rated source table (A1–F6 codes), add/edit dialog
  - Tab 2 Hypotheses: type-badged cards, status workflow, rejection rationale enforcement
  - Tab 3 ACH Matrix: interactive grid with C/I/N/NA cell toggles, hypothesis inconsistency scores and rank badges
  - Tab 4 Conclusions: IC confidence badge, WEP phrase selector, IC statement preview, alternative explanations panel with completeness indicator

#### Real-Time Alerting & Infrastructure Monitoring
- **`alert_engine.py`** — Watchlist and alerting data layer: 9 target types, 14 alert types, snapshot diffing engine
- **`monitoring_scheduler.py`** — Daemon background thread: configurable check intervals (1h–7d), free collectors (DNS, crt.sh, WHOIS, AbuseIPDB), on-demand trigger API
- **`blueprints/monitoring.py`** — Full watchlist and alert management REST API
- **`frontend/src/pages/Monitoring.tsx`** — Monitoring dashboard (route `/monitoring`):
  - Watchlist tab: asset cards with type icons, enable/disable, check-now button, alert badge counts
  - Alerts tab: severity filter chips, status filter, diff summary display, Acknowledge/Resolve/Dismiss actions, 30s auto-refresh
- Sidebar navigation: added **Monitoring** entry with MonitorHeart icon

#### Service Configuration UI & API Key Management
- **`service_config.py`** — Central service catalog with 19 intelligence services categorised by tier (free / freemium / paid) and category (network, threat, social, AI, breach). Persists API keys to `service_config.json` and injects them into `os.environ` on startup so existing code requires no changes.
- **`blueprints/settings.py`** — New Flask blueprint exposing `/api/settings/*` endpoints:
  - `GET  /api/settings/services` — full catalog with live key/operational status
  - `POST /api/settings/services/{id}/enable|disable` — toggle a service
  - `POST /api/settings/services/{id}/key` — save API key (auto-enables service)
  - `DELETE /api/settings/services/{id}/key` — remove key (auto-disables if required)
  - `POST /api/settings/services/{id}/test` — live validation call to the upstream API
  - `GET/POST /api/settings/mode` — read/switch Demo ↔ Live mode
- **`frontend/src/pages/Settings.tsx`** — Complete Settings page rewrite:
  - **Services tab**: filter chips by category and tier; services grouped as *Free*, *Free Tier Available*, *Optional Premium*; per-service cards with name, tier badge, operational status chip, description, rate-limit note, direct signup link, API key input (show/hide), Save, Test Connection, and Remove actions with live test result feedback
  - **Mode & General tab**: visual Demo vs Live mode selector cards; 4-step Quick Start Guide
  - **Status summary bar**: shows operational service count and free-tier count at a glance
- **9 services operational with zero configuration**: DNS, WHOIS, Certificate Transparency (crt.sh), IP Geolocation, MalwareBazaar, ThreatFox, URLScan.io, Have I Been Pwned (password check), GitHub — all free, no API keys required
- Platform registered `settings_bp` blueprint in `app.py`

#### Intelligence Correlation Engine
- Entity extraction from investigation data (domains, IPs, emails, hashes)
- Cross-source relationship mapping and confidence scoring
- Automated timeline reconstruction with event correlation
- Weighted confidence scoring based on source reliability

#### Advanced Analysis Features
- MITRE ATT&CK framework mapping with 14 tactics coverage
- 6-category risk scoring engine (infrastructure, data breach, social engineering, malware, financial, overall)
- Executive summary generation with key findings
- Trend analysis with historical comparison

#### Frontend Component Library (TypeScript)
- Design system with centralized theme and design tokens
- Common components: Button (6 variants), Card (4 variants), Modal, FormField, StatusIndicator, Loading, Toast
- Layout components: Header, Sidebar, responsive Layout wrapper
- 229+ component tests with comprehensive coverage

#### Visualization Components
- Chart components: LineChart, BarChart, PieChart, AreaChart using Recharts
- RiskGauge: Circular gauge with risk level thresholds and labels
- TimelineChart: Vertical timeline with expandable event details
- NetworkGraph: Force-directed graph for entity relationships
- Heatmap: Grid-based color intensity visualization
- StatCard: KPI cards with trends and sparklines
- ThreatMatrix: MITRE ATT&CK style tactic/technique display
- DataTable: MUI DataGrid wrapper with search, filter, and export
- 85+ visualization tests

#### Accessibility & UX Enhancements (WCAG 2.1)
- Custom hooks: useKeyboardNavigation, useFocusTrap, useAnnounce, useMediaQuery
- A11y components: SkipLinks, VisuallyHidden, ErrorBoundary, FocusRing
- Color contrast utilities (WCAG AA/AAA compliance checking)
- Form validation utilities with 15+ validators (email, URL, domain, IP, hash)
- 120+ accessibility and utility tests

#### Data Source Expansion
- 6 new intelligence source collectors
- Caching service with TTL support
- Connection pooling for improved performance

#### Infrastructure
- Comprehensive monitoring stack with Prometheus and Grafana
- Automated health monitoring with 5-minute interval checks
- Custom metrics exporter for OSINT-specific metrics
- Multiple HashiCorp Vault deployment options (minimal, dev, production)
- Job queue system for background task processing
- Structured logging and observability modules (currently disabled for Docker compatibility)
- IMPROVEMENT_ROADMAP.md with 12-month development plan
- Automated CLAUDE.md updates via update-claude.sh script

### Changed
- Backend switched to production mode (FLASK_ENV=production)
- MCP server URLs updated to enhanced versions with new ports:
  - Infrastructure: 8021
  - Threat: 8020
  - AI/Technical: 8050
  - Social: 8010
  - Financial: 8040
- PostgreSQL host renamed to osint-platform-postgresql
- Simplified PostgreSQL audit schema using JSON details column
- Authentication updated to support email-based login
- Frontend image updated to v2.0.1

### Fixed
- Investigation tracking bug (self.investigations -> self.active_investigations)
- Python 3.11 compatibility issues with OpenTelemetry
- Authentication to support both email and username login
- **CI pipeline** — backend tests were exiting with code 4 (collection error) due to `APP_DATA_DIR` not being set before app import in `conftest.py`; fixed by adding env var before the import
- **Duplicate `IntelligenceResult` dataclass** — canonical definition moved to `models.py`; `mcp_clients.py` now re-imports from there
- **`AioHTTPClientInstrumentor` import** — guarded with `try/except` since the package is unavailable on Python 3.11
- **`problem_json.py`** — called non-existent `get_current_trace_id()`; corrected to `get_or_create_trace_id()`
- **Social media MCP server** — `data` variable could raise `NameError` in `except` clause; initialised before `try` block
- **Frontend unused imports** — removed `AnimatePresence` (Card), `Tooltip` (MITREDashboard), `AssessmentIcon` (ExecutiveSummary), `within` (visualizations.test), `waitFor` (Modal.test), `toastId`/`setToastId` (Toast.test)
- **CI config** — switched from ignoring entire test files to `--deselect`ing only the specific tests that require live Postgres/Redis/Vault infrastructure

### Maintenance
- **`.gitignore`** — added comprehensive Python (`__pycache__`, `*.pyc`, `htmlcov/`), Node.js (`node_modules/`, `frontend/coverage/`), IDE, and OS exclusions; removed all previously-tracked build artifacts from git history
- **Unit test coverage** — added 143 new tests across 5 new modules: `test_analytic_tradecraft.py` (38 tests), `test_alert_engine.py` (35 tests), `test_service_config.py` (23 tests), `test_credential_intel_service.py` (21 tests), `test_monitoring_scheduler.py` (26 tests)

### Security
- Vault integration for secure secret management
- JWT authentication improvements
- Production-ready security configurations

## [2.0.1] - 2024-08-17

### Changed
- Frontend image version update
- API URL configuration fixes

## [2.0.0] - 2024-08-16

### Added
- Complete DR Roadmap documentation
- Updated Helm Chart v2.0 with production features
- Professional PDF report generation
- 1-hour investigation lifecycle
- Persistent audit history

### Changed
- Major documentation and architecture updates
- Enhanced MCP server implementations
- Improved compliance framework

## [1.0.0] - 2024-08-12

### Added
- Initial release of Enterprise OSINT Platform
- Multi-agent investigation system
- Flask backend with JWT authentication
- React frontend with Material-UI
- PostgreSQL audit database
- Redis session management
- Kubernetes-native deployment
- MCP servers for specialized intelligence gathering:
  - Infrastructure intelligence
  - Social media intelligence
  - Threat intelligence
  - Financial intelligence
  - Technical intelligence
- GDPR/CCPA/PIPEDA compliance framework
- Professional report generation

### Security
- JWT-based authentication system
- Role-based access control (RBAC)
- Secure API communication
- Kubernetes secrets management

[Unreleased]: https://github.com/yourusername/enterprise-osint-flask/compare/v2.0.1...HEAD
[2.0.1]: https://github.com/yourusername/enterprise-osint-flask/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/yourusername/enterprise-osint-flask/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/yourusername/enterprise-osint-flask/releases/tag/v1.0.0