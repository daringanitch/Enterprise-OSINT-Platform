# Quick Start Guide

Get the Enterprise OSINT Platform running in under 5 minutes!

## Option 1: One-Command Demo (Recommended)

```bash
./start.sh demo
```

That's it! Open http://localhost:8080 and login with `admin` / `admin123`

## Option 2: Interactive Setup

```bash
./start.sh
```

Choose your deployment mode from the menu.

## Option 3: Docker Compose Directly

```bash
docker compose -f docker-compose.demo.yml up -d
```

## What You Get

The demo starts two things: the **full Flask backend** (all 160+ API endpoints operational) and a
**lightweight legacy frontend** (`simple-frontend`) that exposes a small subset of the UI.

| Feature | Demo (`simple-frontend`) | Full Platform (React + k8s) |
|---------|--------------------------|------------------------------|
| Web Interface | http://localhost:8080 | http://localhost:8080 (React) |
| API | http://localhost:5001 | http://localhost:5001 |
| Sample investigations | 5 pre-loaded | unlimited |
| Report generation | ✅ PDF reports | ✅ PDF + STIX 2.1 export |
| External APIs | Simulated (no keys needed) | Live (add API keys to `.env`) |
| Database | PostgreSQL (auto-configured) | PostgreSQL (auto-configured) |
| MITRE ATT&CK matrix | ❌ (API only) | ✅ Interactive + Navigator export |
| Graph intelligence | ❌ (API only) | ✅ Full network graph UI |
| Credential intelligence | ❌ (API only) | ✅ HIBP / Dehashed / Hudson Rock |
| Threat actor dossiers | ❌ (API only) | ✅ 26-actor library with TTP scoring |
| Compliance dashboards | ❌ (API only) | ✅ GDPR / CCPA / HIPAA |
| Monitoring / watchlists | ❌ (API only) | ✅ Real-time diffing + alerts |
| Live analyst collaboration | ❌ (API only) | ✅ Socket.IO presence + annotations |
| Command Palette (⌘K) | ❌ | ✅ Keyboard-first navigation |
| Saved searches + alerts | ❌ | ✅ Toast notifications on match |
| Kanban investigation board | ❌ | ✅ 5-column operational view |
| Entity hover preview cards | ❌ | ✅ Inline popover on any IOC |
| Freshness / decay badges | ❌ | ✅ Color-coded IOC age tiers |
| Evidence chain viewer | ❌ | ✅ Confidence chain per finding |

> **Bottom line:** The demo is a great way to try the API and core investigation workflow. For
> the full analyst experience, deploy the React frontend via Kubernetes (`./start.sh k8s`) or
> the production Docker Compose stack. See the
> [Demo vs. Full Platform section in README.md](README.md#demo-vs-full-platform) for details.

## Default Login

- **Username:** `admin`
- **Password:** `admin123`

## Quick Commands

```bash
./start.sh status   # Check if services are running
./start.sh logs     # View service logs
./start.sh stop     # Stop all services
```

## Adding Real API Keys (Optional)

Create a `.env` file:

```bash
OPENAI_API_KEY=your-key
VIRUSTOTAL_API_KEY=your-key
SHODAN_API_KEY=your-key
```

Then run:

```bash
./start.sh local
```

## Troubleshooting

**Services not starting?**
```bash
docker compose -f docker-compose.demo.yml logs
```

**Port already in use?**
```bash
# Check what's using port 8080 or 5001
lsof -i :8080
lsof -i :5001
```

**Need to reset everything?**
```bash
./start.sh stop
docker volume rm enterprise-osint-platform_demo_postgres_data
./start.sh demo
```

## Seed the Demo Investigation

Load the "Operation SHATTERED PANE" phishing infrastructure scenario:

```bash
APP_DATA_DIR=/tmp/osint_demo python simple-backend/demo_scenario.py
```

Then open http://localhost:5001 and you'll find a pre-populated investigation with:
- 7 phishing domains and a C2 IP
- 8 Admiralty-rated intelligence items
- ACH matrix with 3 hypotheses
- 3 watchlists and live alerts

See [DEMO_SCRIPT.md](DEMO_SCRIPT.md) for the full 10-minute walkthrough.

## Next Steps

1. Create a new investigation from the dashboard
2. Try the "Operation SHATTERED PANE" demo scenario above
3. Apply an investigation template: `POST /api/templates/apt_attribution/apply`
4. Generate a PDF report
5. Check the API at http://localhost:5001/health

### Ready for the Full Platform?

To unlock all 16 React UI pages and the complete analyst feature set:

```bash
# Kubernetes (recommended for production)
./start.sh k8s

# — or Docker Compose with React frontend —
docker compose up -d
```

See [README.md → Demo vs. Full Platform](README.md#demo-vs-full-platform) for the complete
feature comparison and [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for production setup.

For full documentation, see [README.md](README.md).
