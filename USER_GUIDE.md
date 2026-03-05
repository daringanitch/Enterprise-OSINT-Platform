# User Guide — Enterprise OSINT Platform

A page-by-page walkthrough of the full React frontend. All pages require you to be logged in.
Default credentials: **admin / admin123**.

---

## Table of Contents

1. [Logging In](#1-logging-in)
2. [Dashboard](#2-dashboard)
3. [Investigations — List View](#3-investigations--list-view)
4. [New Investigation](#4-new-investigation)
5. [Investigation Detail](#5-investigation-detail)
6. [Graph Intelligence](#6-graph-intelligence)
7. [Threat Analysis (MITRE ATT&CK)](#7-threat-analysis-mitre-attck)
8. [Analytic Workbench](#8-analytic-workbench)
9. [Reports](#9-reports)
10. [Threat Intelligence](#10-threat-intelligence)
11. [Compliance](#11-compliance)
12. [Credential Intelligence](#12-credential-intelligence)
13. [Monitoring & Watchlists](#13-monitoring--watchlists)
14. [Team](#14-team)
15. [Data Sources](#15-data-sources)
16. [Settings](#16-settings)
17. [Cross-Cutting Features](#17-cross-cutting-features)

---

## 1. Logging In

Navigate to `http://localhost:8080` (or your deployed frontend URL). You will land on the login
page automatically if you are not authenticated.

- Enter your username and password, then click **Sign In**.
- On success you are redirected to the Dashboard.
- Your JWT is stored in memory; it expires after the configured session timeout. The page will
  return you to login automatically when it expires.

**Demo credentials:** `admin` / `admin123`

---

## 2. Dashboard

**Sidebar → Dashboard** (`/dashboard`)

The landing page after login. It gives a live read-out of platform health and recent activity.

### What's on the page

- **KPI cards** — four stat tiles showing Active Investigations, Threats Analyzed, Detection
  Rate, and Reports Generated. These update in real time.
- **Risk heatmap** — a colour-coded matrix visualising threat severity vs. volume across your
  current investigation set.
- **Recent investigations** — a condensed list of the last few updated investigations with quick
  links to open them.
- **Alert feed** — the most recent watchlist and monitoring alerts, with type icons (DNS, cert,
  port scan, keyword hit).
- **API / MCP service health** — green/amber/red indicators for each backend service. Useful for
  spotting when an intelligence source is down or missing API keys.

### Tips

- Click any KPI card or recent investigation to drill straight into it.
- The health indicators link to the Data Sources page for remediation.

---

## 3. Investigations — List View

**Sidebar → Investigations → Active / History / Saved** (`/investigations`)

### Switching views

The toolbar has two toggle buttons:
- **List view** (default) — a sortable, filterable table.
- **Kanban view** — a 5-column operational board: New → Active → Analysis → Reporting → Closed.
  Drag cards between columns to update investigation status. Your preference is saved per user.

### Filtering and searching

- The **search bar** filters by target, title, or any text field.
- Dropdown filters for **Status**, **Priority**, and **Risk Level** can be combined.
- Click **Save Search** to store the current filter combination. A **Toast notification** will
  fire the next time you visit if new investigations match the saved criteria since your last
  visit.

### Freshness badges

Every IOC in the list displays a colour-coded age badge:

| Badge | Colour | Age |
|-------|--------|-----|
| Fresh | 🟢 Green | < 7 days |
| Recent | 🔵 Blue | 7–30 days |
| Aging | 🟠 Orange | 30–90 days |
| Stale | 🔴 Red | 90–180 days |
| Expired | ⚫ Grey | > 180 days |

A warning icon appears when IP ownership or domain sinkholing may have changed.

### Opening an investigation

Click any row or card to open the Investigation Detail page.

---

## 4. New Investigation

**Sidebar → Investigations → Active → "+ New Investigation" button** (`/investigations/new`)

### Starting from a template

Six analyst-ready templates are available. Choose one to pre-populate the investigation type,
recommended data sources, and initial tasking:

| Template | Use case |
|----------|----------|
| APT Attribution | Nation-state or advanced threat actor campaign |
| Ransomware | Active ransomware incident or infrastructure |
| Phishing | Phishing kit, credential harvester, or lure |
| M&A Due Diligence | Pre-acquisition cyber risk assessment |
| Insider Threat | Internal actor or data exfiltration investigation |
| Vulnerability Exposure | Asset exposure and CVE impact analysis |

### Starting from scratch

Fill in the **Target** (domain, IP, email address, or hash), select an **Investigation Type**,
set **Priority**, and optionally add a description and tags. Click **Create Investigation** to
launch the 7-stage orchestration workflow.

---

## 5. Investigation Detail

**Investigations list → click any investigation** (`/investigations/:id`)

This is the main workspace for an active investigation.

### Workflow progress bar

A 7-stage progress indicator at the top shows where the investigation currently sits:

1. Initialised
2. Intelligence gathering
3. Correlation
4. Analysis
5. Graph sync
6. Reporting
7. Complete

### Tabs and sections

- **Overview** — target summary, risk score gauge, top findings, and quick-action buttons
  (Generate Report, Run Analysis, Sync to Graph).
- **Findings** — all raw intelligence results from MCP servers, grouped by source. Click any
  finding to expand it and see the evidence chain.
- **Entities** — extracted IOCs (IPs, domains, emails, hashes, certificates, ASNs) with type
  icons. Hover any entity to see the **Entity Hover Preview Card** (risk score, linked
  investigations, last seen, top findings) without navigating away.
- **Pivot Suggestions** — ranked next-pivot recommendations generated by the pivot engine. Each
  suggestion shows a composite score based on threat flag, corroboration, centrality, recency,
  and whether it is still unresolved. Click a suggestion to launch a new enrichment.
- **Correlations** — shared indicators detected across all other investigations. Useful for
  spotting infrastructure reuse by the same threat actor.
- **Timeline** — automated event sequencing with confidence scoring, showing how the activity
  unfolded chronologically.
- **Collaboration panel** — see which analysts currently have the investigation open (presence
  bar with avatars), and read or write shared annotations in real time.

### Navigation to deeper analysis

Three tabs at the top of the detail view link to investigation-scoped pages:

- **Graph** → Graph Intelligence
- **Threats** → Threat Analysis
- **Workbench** → Analytic Workbench

---

## 6. Graph Intelligence

**Inside an investigation → "Graph" tab** (`/investigations/:id/graph`)

A Palantir-style interactive network graph that maps every entity and relationship extracted from
the investigation.

### Reading the graph

- **Nodes** represent entities (35+ types: IP, domain, email, organisation, certificate, ASN,
  malware family, threat actor, etc.). Node size reflects centrality — larger nodes are more
  connected and influential in the network.
- **Edges** represent relationships (45+ types: resolves-to, hosted-on, registered-by, linked-to,
  shares-infrastructure, etc.).
- **Colour coding** — nodes are coloured by entity type; edges by relationship category.

### Interacting with the graph

- **Click a node** to see its details panel on the right: entity metadata, risk score, connected
  nodes, and top findings.
- **Drag nodes** to rearrange the layout.
- **Scroll / pinch** to zoom in and out.
- **Filter panel** — toggle entity types and relationship types on/off to declutter large graphs.

### Analytics panel

The right-hand panel surfaces pre-computed graph analytics:

- **PageRank** — which nodes are most important by link structure (equivalent to "how many
  high-value nodes point to this node").
- **Betweenness centrality** — which nodes are critical bridges between clusters (removing them
  would disconnect the graph).
- **Community detection** — Louvain or label propagation algorithms group nodes into clusters
  that likely belong to the same infrastructure or campaign.
- **Blast radius** — enter any node to calculate the estimated impact if that asset were
  compromised: how many downstream nodes are reachable, and what their aggregate risk score is.

### Syncing

Click **Sync to Graph** (also available from the Investigation Detail overview) to push the
latest findings into the graph database. The graph updates in place.

---

## 7. Threat Analysis (MITRE ATT\&CK)

**Inside an investigation → "Threats" tab** (`/investigations/:id/threats`)

Maps investigation findings to the MITRE ATT&CK Enterprise framework.

### Reading the matrix

- The full 14-tactic × N-technique grid is rendered as a heat map.
- **Cells with evidence** are highlighted; brighter cells indicate more corroborating findings.
- **Coverage mode** shows which techniques have been assessed (even if no evidence was found),
  useful for gap analysis.
- **Click any technique cell** to see the supporting evidence: which findings triggered the
  mapping, confidence level, and links back to the source findings.

### Selecting and exporting

- Click technique cells to select them (they turn blue). Selected techniques are highlighted
  across the matrix.
- Click **Export to ATT&CK Navigator** to download a `.json` layer file compatible with
  `navigator.attack.mitre.org`. Open the Navigator site and import the file to share your
  coverage map with stakeholders.

---

## 8. Analytic Workbench

**Inside an investigation → "Workbench" tab** (`/investigations/:id/workbench`)

Structured analytic techniques for defensible, auditable intelligence production.

### Intelligence Items (Admiralty Scale)

Each piece of intelligence is rated on the **NATO Admiralty scale**:

- **Source reliability** — A (Completely Reliable) to F (Cannot Be Judged)
- **Information credibility** — 1 (Confirmed) to 6 (Cannot Be Judged)

Add items via **+ Add Item**, fill in the source, content, and select ratings from the dropdowns.
Items feed into the ACH matrix and conclusion confidence calculations.

### ACH Matrix (Analysis of Competing Hypotheses)

The ACH matrix helps analysts test evidence against multiple hypotheses to avoid confirmation
bias.

1. Click **+ Add Hypothesis** and define at least two competing explanations (primary,
   alternative, devil's advocate, or null hypothesis).
2. For each cell in the matrix (evidence row × hypothesis column), select whether the evidence
   is **Consistent**, **Inconsistent**, **Not Applicable**, or **Neutral**.
3. The matrix scores each hypothesis — the one with the fewest inconsistencies is the most
   diagnostic.

### Conclusions

Record formal analytic conclusions with:
- **Confidence level** — High, Moderate, or Low (IC-standard definitions)
- **Supporting hypotheses** — link to ACH hypotheses
- **Evidence chain** — the visual `source → finding → inference → conclusion` chain, where chain
  confidence is the geometric mean of all node scores (a weak link degrades the whole chain)

---

## 9. Reports

**Sidebar → Reports** (`/reports`)

### Generating a report

Open any investigation and click **Generate Report** (from the Overview tab or the Reports page
itself). Choose:
- **Executive Summary** — high-level narrative for management, risk score, top recommendations
- **Technical Report** — full findings, IOC tables, methodology, and evidence chain
- **STIX 2.1 Bundle** — machine-readable threat intelligence export for ingestion into a SIEM,
  TIP, or sharing platform

### Report library

The Reports page lists all generated reports across all investigations, with filters for type,
date range, and status. Click any report to download or preview it.

### Scheduled reports

Configure recurring report generation (daily, weekly, or on investigation closure) via the
scheduled run settings at the bottom of the page.

---

## 10. Threat Intelligence

**Sidebar → Threat Intelligence** (`/threat-intelligence`)

A library of 26 known threat actor dossiers, mapped to MITRE ATT&CK.

### Browsing actors

- Use the **sector filter** to narrow to actors that target your industry.
- Use the **technique filter** to find actors that use specific ATT&CK techniques.
- Each actor card shows: aliases, origin, primary sectors targeted, top techniques, and a summary.

### TTP Overlap Scoring

Click **Match by TTPs** and paste in a list of ATT&CK technique IDs observed in your
investigation (e.g. `T1566.001, T1071.001`). The page ranks all 26 actors by overlap score —
how many of the observed techniques match that actor's known TTPs. High overlap = strong
attribution signal.

### Actor Dossiers

Click any actor card to open the full dossier: history, attributed campaigns, full technique
list with sub-techniques, sector targets, and links to public reporting.

---

## 11. Compliance

**Sidebar → Compliance** (`/compliance`)

Tracks your organisation's posture against three frameworks.

### Supported frameworks

| Framework | Scope |
|-----------|-------|
| GDPR | EU data protection and privacy |
| CCPA | California consumer privacy |
| HIPAA | US healthcare data protection |

### Running an assessment

Click a framework card to start an assessment. The platform queries your investigation data and
audit trail to automatically map findings to controls. When complete, you see:
- **Coverage score** — percentage of controls assessed
- **Gaps** — controls with no evidence or failing evidence
- **Remediation suggestions** — recommended actions per gap
- **Evidence mapping** — which investigation findings satisfy each control

Assessment history is stored so you can track improvement over time.

---

## 12. Credential Intelligence

**Sidebar → Credentials** (`/credentials`)

Checks email addresses, domains, and passwords against breach and paste databases.

### Email lookup

Enter an email address and click **Check Email**. Results show:
- **HIBP breaches** — named data breaches the address appears in
- **HIBP pastes** — paste sites (Pastebin, etc.) where the address was found
- **Dehashed** — additional breach records with partial credential data
- **Hudson Rock** — infostealer-specific exposure (Redline, Vidar, etc.)

### Domain lookup

Enter a domain to check exposure across all email addresses at that domain — useful for
assessing an acquisition target or a supply chain partner.

### Password check (k-anonymity)

Enter a password (or hash) to check if it appears in known breach databases. The check uses
**k-anonymity** — only the first 5 characters of the SHA-1 hash are sent to the API, so your
actual password is never transmitted.

### Source status panel

The bottom of the page shows the operational status of each intelligence source (HIBP,
Dehashed, Hudson Rock, paste monitoring) — green means live and responding, amber means limited
(e.g., rate-limited), red means the source needs an API key or is unreachable.

---

## 13. Monitoring & Watchlists

**Sidebar → Monitoring** (`/monitoring`)

Continuously watches targets for changes and fires alerts when something new is detected.

### Creating a watchlist entry

Click **+ Add to Watchlist** and specify:
- **Target** — domain, IP, email, or keyword
- **Alert on** — check any combination of: DNS changes, new certificates, port changes, keyword
  appearances
- **Check interval** — how frequently the platform re-queries the target (minimum 15 minutes)

### Alerts feed

The right panel shows all fired alerts, newest first. Each alert shows:
- The watchlist entry that triggered it
- Alert type icon (DNS, cert, port, keyword)
- **Snapshot diff** — a before/after comparison showing exactly what changed (e.g. a new A
  record, a new open port, a new certificate SAN)

### Stats bar

At the top: total watchlist entries, new alerts since your last visit, and last check timestamp.

---

## 14. Team

**Sidebar → Team** (`/team`)

Manage users and their access levels.

### Roles

| Role | Capabilities |
|------|-------------|
| Admin | Full access — create/delete users, change settings, access all investigations |
| Analyst | Create and work investigations, generate reports, use all analysis tools |
| Viewer | Read-only access to investigations and reports |

### Managing users

- Click **+ Invite User** to create a new account (username, email, role).
- Click any user row to edit their role or reset their password.
- The **Audit Trail** tab shows a timestamped log of all user actions across the platform —
  useful for compliance evidence and insider threat monitoring.

---

## 15. Data Sources

**Sidebar → Data Sources** (`/data-sources`)

Displays the status and configuration of all five MCP intelligence microservices.

### Services

| Service | Port | Capabilities |
|---------|------|-------------|
| Infrastructure Advanced | 8021 | DNS resolution, WHOIS, SSL certificates, subdomain enumeration, port scanning |
| Threat Aggregator | 8020 | VirusTotal, Shodan, AbuseIPDB, AlienVault OTX |
| Social Media Enhanced | 8010 | Multi-platform social profile analysis |
| Financial Enhanced | 8040 | SEC EDGAR filings, company research |
| AI Analyzer | 8050 | GPT-4 powered threat assessment and narrative generation |

### Status indicators

Each service card shows:
- **Operational** — service is reachable and API keys are configured
- **Limited (no key)** — service is running but no API key has been set; some endpoints return
  mock data
- **Needs API Key** — service requires a key before it can return real results
- **Disabled** — service has been turned off (toggle on the Settings page)

Click any service card to jump to its configuration in Settings.

---

## 16. Settings

**Sidebar → Settings** (`/settings`)

Two tabs: **Intelligence Services** and **Mode & General**.

### Intelligence Services tab

Lists all integrations categorised by tier:
- **Free — No API Key Needed** (e.g. WHOIS, DNS, SSL)
- **Free Tier Available** (e.g. VirusTotal, Shodan — free keys available)
- **Optional Premium** (e.g. Dehashed, full Shodan API)

For each service:
1. Click the **key icon** to expand the configuration panel.
2. Paste your API key into the input field and click **Save Key**. The key is stored in Vault
   (production) or as an environment variable (demo mode).
3. Click **Test Connection** to verify the key is valid before saving.
4. Use the toggle to **enable or disable** a service without removing its key.

### Mode & General tab

- **Demo Mode / Live Mode** toggle — switches the backend between `demo` and `production`
  operating modes. This is the in-UI equivalent of the `OPERATION_MODE` environment variable.
- Notification preferences, theme, and other platform-wide settings.

#### Understanding Demo Mode vs. Live Mode

There are two independent layers that control what data you see:

**Layer 1 — Operating mode (`OPERATION_MODE`)**

| Mode | What the backend serves |
|------|------------------------|
| **Demo** (default) | Pre-seeded synthetic investigations and mock findings. API keys, even if configured, are intentionally ignored. |
| **Live** (production) | Real investigation data from the database. External API calls are made when keys are available. |

The platform defaults to Demo mode unless `OPERATION_MODE=production` is set in the environment
at startup — or until you toggle it here. Toggling in the UI persists the choice across restarts
(stored in `/app/data/mode_config.json`).

> If you deployed via `./start.sh k8s` or `kubectl apply -f k8s/` and see only sample
> investigations, this is why — the k8s manifests do not set `OPERATION_MODE` by default.
> Toggle to Live mode here, or add `OPERATION_MODE: production` to the backend deployment
> manifest for it to take effect from startup.

**Layer 2 — API keys (per-service)**

Switching to Live mode does not require any API keys. The platform is designed so every service
works in some form without one:

- **Free services** (DNS, WHOIS, SSL, port scanning) — fully operational, no key ever needed
- **Freemium services** (VirusTotal, Shodan, AbuseIPDB) — return empty or minimal results
  without a key; add a free key on the provider's website to unlock real data
- **Paid/optional services** (Dehashed, Hudson Rock) — skipped entirely during enrichment
  until a key is configured
- **AI analysis** (OpenAI) — narrative summaries and GPT-4 threat profiles are skipped;
  structured findings are still returned from other sources

You can add, test, and remove keys at any time on the **Intelligence Services** tab without
redeploying. See [DEPLOYMENT_GUIDE.md → Operating Modes](DEPLOYMENT_GUIDE.md#operating-modes)
for how to configure this at the infrastructure level.

---

## 17. Cross-Cutting Features

These features are available from every page in the platform.

### Command Palette (⌘K / Ctrl+K)

Press **⌘K** on Mac or **Ctrl+K** on Windows/Linux at any time to open the Command Palette.

- **Type a page name** (e.g. "compliance") to navigate there instantly.
- **Type an investigation name or target** to open it directly.
- **Paste an IOC** (IP, domain, email, hash) to trigger fan-out enrichment immediately — all 5
  MCP servers are queried in parallel and results stream back as a live timeline without you
  needing to create a formal investigation first.

### Live Analyst Collaboration

When multiple analysts have the same investigation open simultaneously:
- The **Presence Bar** at the top of the investigation shows avatar icons for each connected
  analyst with their live status.
- The **Annotation Panel** (right-hand side of the Investigation Detail) shows a real-time feed
  of shared notes. Type a note and hit Enter — it appears instantly for every analyst in the
  room, with entity tagging (type `@` to tag an IOC and link it to findings).

### Unified IOC Enrichment ("Investigate This")

On any entity chip or in the Command Palette, click **Investigate This** on an IOC. This fans
out to all 5 MCP servers in parallel and streams findings back as a live Server-Sent Events
(SSE) timeline. You see each source resolve in real time with findings, confidence level, and
risk score — without creating a full investigation.

### Entity Hover Preview Cards

Hover over any IP address, domain, email, or hash anywhere in the platform to see a rich
popover showing:
- Risk score
- Entity type and metadata
- Linked investigations
- Last seen timestamp
- Top findings

Click **Open** in the popover to navigate to the full entity detail without leaving your current
page.

### Indicator Freshness / Decay Badges

Every IOC across the platform displays a colour-coded age badge (see the table in
[Investigations — List View](#3-investigations--list-view)). When an IOC crosses into the
**Stale** or **Expired** tier, a warning tooltip explains that IP ownership or domain sinkholing
may have changed and the indicator should be re-validated.

### Evidence Chain Viewer

Click the chain icon on any finding to open the **Evidence Chain** panel. This shows a
`source → finding → inference → conclusion` graph where each node has a confidence score.
The overall chain confidence is the **geometric mean** of all node scores — a single weak link
(e.g. a low-confidence inference) degrades the entire chain. Use this to identify which steps in
your analytic logic need more corroboration before including the conclusion in a formal report.

---

*For deployment instructions see [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md). For the complete
API reference see [API_REFERENCE.md](API_REFERENCE.md). For architecture details see
[ARCHITECTURE_OVERVIEW.md](ARCHITECTURE_OVERVIEW.md).*
