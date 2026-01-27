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
| API | http://localhost:5000 |
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
# Check what's using port 8080 or 5000
lsof -i :8080
lsof -i :5000
```

**Need to reset everything?**
```bash
./start.sh stop
docker volume rm enterprise-osint-platform_demo_postgres_data
./start.sh demo
```

## Next Steps

1. Create a new investigation from the dashboard
2. Explore the pre-loaded sample investigations
3. Generate a PDF report
4. Check the API at http://localhost:5000/health

For full documentation, see [README.md](README.md).
