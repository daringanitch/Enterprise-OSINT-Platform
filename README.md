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

### Enterprise Features
- **Professional PDF Reports**: Executive and technical summaries
- **Compliance Framework**: GDPR/CCPA assessment
- **Audit Trail**: Complete investigation history
- **Role-Based Access**: Admin, analyst, viewer roles
- **Demo Mode**: Full functionality without API keys

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
├── simple-backend/          # Flask REST API
│   ├── app.py              # Main application (58 endpoints)
│   ├── models.py           # Database models
│   └── tests/              # Test suite
├── simple-frontend/         # React SPA
│   └── index.html          # Single-page application
├── mcp-servers/            # Intelligence microservices
│   ├── infrastructure-advanced/   # Port 8021
│   ├── threat-aggregator/         # Port 8020
│   └── ai-analyzer/               # Port 8050
├── k8s/                    # Kubernetes manifests
├── scripts/                # Organized utility scripts
│   ├── deploy/             # Deployment helpers
│   ├── dev/                # Development tools
│   └── maintenance/        # System maintenance
├── start.sh                # One-command setup
└── docker-compose.demo.yml # Demo deployment
```

## API Quick Reference

```bash
# Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Start Investigation
curl -X POST http://localhost:5000/api/investigations \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "investigation_type": "comprehensive"}'

# Get Results
curl http://localhost:5000/api/investigations/{id} \
  -H "Authorization: Bearer YOUR_TOKEN"
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

## Technology Stack

- **Backend**: Flask, SQLAlchemy, PostgreSQL, Redis
- **Frontend**: React 18, Material-UI, Axios
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
