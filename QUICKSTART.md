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

| Feature | Demo Mode |
|---------|-----------|
| Web Interface | http://localhost:8080 |
| API | http://localhost:5001 |
| Sample Investigations | 5 pre-loaded |
| Report Generation | Full PDF reports |
| External APIs | Simulated (no keys needed) |
| Database | PostgreSQL (auto-configured) |

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

For full documentation, see [README.md](README.md).
