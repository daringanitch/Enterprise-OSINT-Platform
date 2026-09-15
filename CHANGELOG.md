# Changelog

All notable changes to the Enterprise OSINT Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

#### The backend was never actually connected to the infrastructure MCP
`simple-backend/mcp_clients.py` posts to `http://mcp-infrastructure-enhanced:8021/execute`, but that server exposed only `/mcp` (`method`/`params` → `data`) and REST-style `/infrastructure/<tool>` routes. Every infrastructure call failed, was swallowed by a broad `except`, and the orchestrator fell back to **simulated data** — the `"Falling back to simulated infrastructure data due to MCP failure"` path. WHOIS, DNS, SSL, and geolocation intelligence never reached the backend from this server.

Four independent mismatches had to be closed: the path, the request keys (`tool`/`parameters` vs `method`/`params`), the response key (`result` vs `data`), and the tool names — `whois_lookup`, `dns_records`, and `ssl_certificate_info` existed under **no** route at all.

- **`mcp-servers/infrastructure-advanced/app.py`** — Adds `InfrastructureAdvancedMCPServer.execute_tool()` and a thin `/execute` route implementing the contract `social-media-enhanced` and `financial-enhanced` already use. Adds public `whois_lookup`, `dns_records`, and `ssl_certificate_info` methods returning the key names the backend reads; the existing private helpers that feed `comprehensive_recon` are untouched, as are `/mcp` and the `/infrastructure/*` routes.
- **`simple-backend/mcp_clients.py`** — DNS results now carry the `records` dict keyed by record type. The orchestrator extracts A records from `processed['records']['A']`, but the client only emitted flat `a_records`, so **no IPs were ever extracted from DNS** even when the call succeeded. Adds `_gather_geolocation_intelligence()`, which geolocates the addresses DNS resolved (capped at 5 per investigation).
- **`simple-backend/utils/geographical_scope.py`** — Adds `merge_geolocation()`, folding coordinates onto the matching `ip_addresses` entry so they travel with the IP they describe. Preserves DNS provenance, ignores empty values so a partial result cannot blank data another source supplied, and appends an unmatched IP rather than dropping it.
- **`simple-backend/investigation_orchestrator.py`** — Consumes `geolocation` results via that helper.
- **Tests** — `mcp-servers/tests/test_infrastructure_execute.py` (12) pins the wire contract: tool names, request keys, response envelope, and that `/mcp`'s separate shape still works. `simple-backend/tests/unit/test_geolocation_wiring.py` (13) covers the merge and the collection path, including that jurisdiction becomes derivable from a geolocated IP.

**Impact:** live-mode investigations can now receive real infrastructure intelligence. Demo mode is unaffected — `blueprints/investigations.py` short-circuits before the orchestrator runs.

### Security

#### IP geolocation no longer leaks investigation targets to a third party
- **`mcp-servers/infrastructure-advanced/geoip_local.py`** (new) — Resolves IPs in-process from a local MaxMind GeoLite2 City database. Replaces `geoip_lookup()`'s call to **plaintext `http://ip-api.com`**, which sent every investigation target IP unencrypted to a third party, visible to anything on the network path. There is deliberately **no network fallback**: a missing database reports `available: false` rather than silently restoring the egress this change removes.
- **`mcp-servers/infrastructure-advanced/Dockerfile`** — Fetches the GeoLite2 database at build time via `--build-arg MAXMIND_LICENSE_KEY`. The database is not redistributable and is not committed. The image builds and runs without a key; geolocation simply reports unavailable. Also now copies `passive_dns_circl.py` and `cert_chain.py`, which `app.py` imports but the Dockerfile previously omitted.
- **`mcp-servers/infrastructure-advanced/app.py`** — Domain targets are now geolocated via their resolved IP. Previously only literal-IP targets got geolocation at all, leaving compliance jurisdiction with nothing to derive from on domain investigations. Adds the `infrastructure/geolocation` capability and route.
- **`mcp-servers/tests/test_geoip_local.py`** (new) — 16 tests: graceful degradation without a database (including an explicit assertion that no network connection is attempted), private/reserved/invalid address handling, and geoip2 field mapping via a mocked reader so the happy path is covered without shipping a database.
- **`CONFIGURATION.md`** — New "GeoIP Database" section: obtaining a licence key, build-time installation, `GEOIP_DB_PATH`, and verification.
- **`simple-backend/service_config.py`**, **`CONFIGURATION.md`** — The Settings service catalog and the "works without keys" table advertised ip-api.com with its 45 req/min limit. Both now describe the local database: no key and no rate limit at query time.


### Fixed

#### Compliance geographical scope was never derived from investigation data
- **`simple-backend/utils/geographical_scope.py`** (new) — Derives ISO 3166-1 alpha-2 jurisdiction codes from the country data collectors actually store: geolocated IPs (`ip_addresses[].countryCode|country|location`), WHOIS registrant country (`domains[].country`), and Shodan country names (`exposed_services[].country`). `normalize_country()` reconciles the formats sources disagree on (Shodan returns `"United States"`, WHOIS returns `"US"`) and drops unrecognized values rather than guessing, since a wrong jurisdiction is worse than a missing one. `expand_region_aliases()` expands the non-ISO `'EU'` alias into its 27 member-state codes.
- **`simple-backend/investigation_orchestrator.py`** — `_determine_geographical_scope()` read `ip_info['location']`, a key only the *simulated* fallback ever wrote. Every real investigation fell through to the hardcoded `['US', 'EU']` default. Now derives from collected data, falling back to the broad default (with a log line) only when no geographic data was collected at all.
- **`simple-backend/investigation_reporting.py`** — Same dead `location` key, but with no default, so report geographical scope was always empty. Now shares the derivation helper.
- **`simple-backend/compliance_framework.py`** — `_determine_applicable_frameworks()` matches ISO alpha-2 codes, so the literal `'EU'` in the default scope silently matched nothing and **GDPR was never triggered by the fallback path** — only CCPA, via `'US'`. Region aliases are now expanded before matching, regardless of caller.
- **`simple-backend/tests/unit/test_geographical_scope.py`** (new) — 34 tests covering code/name normalization, placeholder rejection, per-source derivation, alias expansion, and a regression guard that `'California'` never normalizes to `'CA'` (Canada), which would falsely trigger PIPEDA.

**Impact:** GDPR, PIPEDA, and LGPD assessments were unreachable for real investigations; every target produced the same hardcoded jurisdiction set. Assessments generated before this fix should be re-run.

---

## [1.2.0] - 2026-03-04

### Added

#### Command Palette (⌘K / Ctrl+K)
- **`frontend/src/hooks/useCommandPalette.ts`** — Global context + keyboard shortcut registration (`⌘K` / `Ctrl+K`). Exposes `open(initialQuery?)` / `close()` to any component via `CommandPaletteContext`.
- **`frontend/src/components/common/CommandPalette.tsx`** — Full-featured modal launcher with fuzzy search across all pages, investigations, and actions. IOC auto-detection: pasting an IP, domain, email, or hash surface "Investigate [value]" as the top result with fan-out enrichment shortcut. Full keyboard navigation (↑↓ Enter Esc) with shortcut hints. Wired globally via `CommandPaletteContext` in `Layout.tsx`.

#### Live Collaboration (Socket.IO)
- **`flask-socketio`** + **`eventlet`** added to `requirements.txt`; SocketIO instance initialised in `app.py` with graceful fallback when package is absent.
- **`simple-backend/blueprints/collaboration.py`** — Investigation-scoped Socket.IO rooms; events: `join_investigation`, `leave_investigation`, `cursor_move`, `update_investigation`, `heartbeat`. REST endpoints: `GET /api/investigations/<id>/annotations`, `POST /api/investigations/<id>/annotations`, `DELETE /api/investigations/<id>/annotations/<aid>`, `GET /api/investigations/<id>/presence`. Annotations broadcast via socket and persist in-memory.
- **`frontend/src/hooks/useCollaboration.ts`** — Socket.IO client hook: presence tracking, real-time annotation feed, cursor broadcasting, 20-second heartbeat, auto-reconnect. Optimistic annotation add/delete with server-side fallback.
- **`frontend/src/components/collaboration/PresenceBar.tsx`** — Colored analyst avatar stack (deterministic color assignment), last-seen tooltip, Live/Offline badge.
- **`frontend/src/components/collaboration/AnnotationPanel.tsx`** — Collapsible side-panel: entity tagging, ⌘↵ submit, real-time feed with avatar + timestamp, per-author delete.

#### Unified IOC Enrichment — "Investigate This" (SSE Fan-out)
- **`simple-backend/blueprints/enrichment.py`** — `GET /api/enrich` and `POST /api/enrich` stream Server-Sent Events as all 5 MCP servers are queried concurrently via `asyncio`/`aiohttp`. Events: `source_start` → `source_result` | `source_error` → `summary` → `done`. Hard 35-second ceiling. `GET /api/enrich/sources` lists configured sources and their applicability by IOC type.
- **`frontend/src/components/enrichment/EnrichmentPanel.tsx`** — Live SSE consumer using `fetch + ReadableStream` (supports auth headers). Source cards animate queued → loading → success/error with risk badges and expandable findings. Summary stat block (findings / max risk / sources / elapsed) on completion.

#### Interactive MITRE ATT&CK Matrix
- **`frontend/src/components/visualizations/MitreMatrix.tsx`** — Full 14-tactic × N-technique interactive grid:
  - **Evidence heat-map mode**: cell opacity and color scale by finding count × severity
  - **Coverage mode**: binary detected/not-detected
  - Click to select technique; Shift/⌘+Click for multi-select; `onSelect` callback emits selected IDs
  - Hover popover: finding count, severity, direct link to attack.mitre.org
  - **ATT&CK Navigator layer export**: one-click `.json` download importable to `navigator.attack.mitre.org`
  - All 14 enterprise ATT&CK tactics hard-coded; live evidence overlaid via `detectedTechniques` prop

#### Confidence Scoring & Evidence Chain
- **`frontend/src/components/analysis/EvidenceChain.tsx`** — Visual `source → finding → inference → conclusion` chain with:
  - Per-node confidence bars color-coded by tier (High ≥85% / Medium ≥65% / Low ≥40% / Speculative)
  - **Chain confidence = geometric mean** of all node scores — a weak link degrades the whole chain (correct epistemics for defensible reports)
  - Corroboration badges for cross-source verification, `FreshnessIndicator` per node
  - Expandable raw detail, collapsible to compact (first 2 nodes) mode
  - Analyst-readable conclusion + assessment block with IC-standard language guidance

#### Analyst UX Improvements (v1.1.x backport)
- **Investigation Kanban View** — `KanbanBoard.tsx` with 5 operational columns (New/Active/Analysis/Reporting/Closed), framer-motion animations, per-column count badges, risk/priority chips, progress bars. List ↔ Kanban toggle in Investigations header, preference persisted in `localStorage`.
- **Entity Hover Preview Cards** — `EntityChip.tsx` + `EntityHoverCard.tsx`: 400ms-debounced MUI Popover showing confidence bar, first/last seen with freshness badge, linked investigation rows. Backend: `GET /api/entities/lookup` aggregates entity intelligence across all investigations.
- **Indicator Freshness/Decay Badges** — `freshness.ts` utility with 5 tiers (fresh <7d, recent 7–30d, aging 30–90d, stale 90–180d, expired >180d). `FreshnessIndicator.tsx` in compact-dot and full-chip modes with decay warning messages. Applied to investigation cards, kanban cards, and entity hover cards.
- **Saved Searches with Alerting** — `SearchBar.tsx`: live client-side filter (text + status/priority/risk dropdowns), save-search modal, collapsible saved-searches panel. `useSavedSearches.ts`: CRUD hook for `GET/POST/DELETE /api/searches`. On-mount Toast notification when new investigations match a saved search since last visit (localStorage timestamp).

### Changed
- `Layout.tsx` wired with `CommandPaletteContext` provider and global `CommandPalette` mount so `⌘K` works on every authenticated page.
- `app.py` — registered `collaboration_bp` and `enrichment_bp` blueprints; conditional SocketIO init with `eventlet` async mode.
- `simple-backend/shared.py` — added `saved_searches: dict = {}` to `_Services` singleton.

### Fixed
- `FreshnessIndicator.tsx` — renamed custom `color` styled-prop to `chipcolor` to avoid collision with MUI Chip's built-in `color` prop (TypeScript error).
- `EntityChip.tsx` — renamed custom `clickable` prop to `isclickable` to avoid collision with MUI Chip's `clickable: boolean` prop.

### Security
- `collaboration.py` — annotation REST endpoints respect existing JWT auth headers; Socket.IO events are room-scoped so cross-investigation leakage is not possible.
- `enrichment.py` — SSE endpoint hard-capped at 35 seconds; individual MCP source timeouts enforced via `aiohttp.ClientTimeout`.

---

## [1.0.0] - 2026-02-26

### Added

#### Pivot Suggestions Engine
- **`pivot_engine.py`** — Stateless pivot recommendation engine with composite scoring across 5 weighted signals: threat_flag (0.35), corroboration (0.25), centrality (0.20), recency (0.10), unresolved edges (0.10). Supports 7 pivot types: expand_infrastructure, check_reputation, check_credentials, lookup_registration, enumerate_subdomains, cert_transparency, social_footprint.
- **`blueprints/pivots.py`** — `GET /api/investigations/<id>/pivots` (ranked suggestions with `max` param), `POST /api/investigations/<id>/pivots/dismiss`, `GET /api/pivots/explain` (scoring documentation endpoint).

#### Threat Actor Dossier Library
- **`threat_actor_library.py`** — 26 nation-state and criminal actor dossiers (APT28, APT29, APT41, Lazarus Group, FIN7, Scattered Spider, and more) with full MITRE ATT&CK technique and tactic mappings, `match_ttps()` overlap scoring, full-text search, sector filtering, and technique filtering.
- **`blueprints/threat_actors.py`** — `GET /api/threat-actors` (filtered list: q, sector, technique, type, motivation), `GET /api/threat-actors/<id>`, `POST /api/threat-actors/match` (technique-to-actor ranking), `POST /api/threat-actors/fingerprint` (auto-extracts TTPs from an investigation and returns ranked actor candidates).

#### Cross-Investigation Correlation
- **`cross_investigation_correlator.py`** — Inverted-index correlation engine detects shared domains, IPs, emails, ASNs, and certificate thumbprints across all investigations with significance classification (critical for shared certs, high for shared IPs/domains/emails, medium for shared ASNs) and composite link-strength scoring.
- **`blueprints/correlations.py`** — `GET /api/correlations` (full platform-wide scan), `GET /api/investigations/<id>/correlations` (links for a specific investigation), `GET /api/correlations/indicators/<value>` (find all investigations containing an indicator).

#### Investigation Templates
- **`investigation_templates.py`** — 6 analyst-ready investigation templates:
  - `apt_attribution` — 8h depth, 180-day history, 4 ACH hypotheses, 11 MITRE techniques, GDPR-compliant
  - `ransomware_profiling` — 6h depth, 365-day history, 3 ACH hypotheses, 9 MITRE techniques
  - `phishing_infrastructure` — 3h depth, 60-day history, 3 ACH hypotheses, 5 MITRE techniques
  - `ma_due_diligence` — 12h depth, corporate records enabled, 3 ACH hypotheses
  - `insider_threat` — GDPR/CCPA compliance, PII handling guidance, 3 ACH hypotheses
  - `vulnerability_exposure` — 5h depth, 30-day history, infrastructure focus
  - Each template includes watchlist seeds with placeholder resolution, ACH hypothesis seeds, recommended MITRE techniques, analyst key questions, and step-by-step analyst guidance.
- **`blueprints/templates.py`** — `GET /api/templates` (with `?category=` filter), `GET /api/templates/categories`, `GET /api/templates/<id>`, `POST /api/templates/<id>/apply` (returns pre-populated scope, watchlist seeds, and ACH hypotheses with optional target resolution).

#### Demo Scenario & Walkthrough
- **`demo_scenario.py`** — Deterministic seeder for "Operation SHATTERED PANE" phishing infrastructure investigation with 7 phishing domains, C2 IP, 8 Admiralty-rated intel items, 3 ACH hypotheses, 24-cell ACH matrix, IC-standard conclusion, devil's advocate challenge, 3 watchlists, and 3 alerts. Supports `--reset` flag.
- **`DEMO_SCRIPT.md`** — 10-minute walkthrough script across 7 scenes: Dashboard → Investigation → Graph → Monitoring → Tradecraft → Credential Intel → Export. Includes objection-handling for competitor comparisons and a 3-minute elevator variant.
- **`Operation_Shattered_Pane.mp4`** — Recorded demo walkthrough video.

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

[Unreleased]: https://github.com/yourusername/enterprise-osint-flask/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/yourusername/enterprise-osint-flask/releases/tag/v1.0.0