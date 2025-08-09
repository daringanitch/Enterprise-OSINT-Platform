# Enterprise OSINT Platform - Flask + React Edition

A professional-grade Open Source Intelligence (OSINT) investigation platform built with Flask backend and React frontend, designed for enterprise deployment with real-time capabilities and scalable architecture.

## 🚀 Key Improvements Over Streamlit Version

- **Production-Ready Architecture**: Flask REST API + React SPA
- **Real Authentication**: JWT tokens, OAuth2/SAML support
- **Background Processing**: Celery for async OSINT investigations
- **Real-time Updates**: WebSocket support for live investigation progress
- **Professional UI**: Custom React components with Material-UI
- **Scalable Design**: Microservices architecture with Redis/PostgreSQL
- **API-First**: RESTful endpoints for third-party integrations

## 🏗️ Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  React Frontend │────▶│   Flask API     │────▶│  MCP Servers    │
│   (TypeScript)  │     │   (REST/WS)     │     │  (OSINT Tools)  │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Background Tasks   │
                    │  (Celery + Redis)   │
                    └─────────────────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    PostgreSQL       │
                    │  (Investigation DB) │
                    └─────────────────────┘
```

## 🛠️ Tech Stack

### Backend
- **Flask 3.0+** - Modern Python web framework
- **Flask-RESTful** - REST API development
- **Flask-SocketIO** - WebSocket support
- **Flask-JWT-Extended** - Authentication
- **SQLAlchemy** - ORM for PostgreSQL
- **Celery** - Distributed task queue
- **Redis** - Cache and message broker
- **Marshmallow** - API serialization

### Frontend
- **React 18+** - UI framework
- **TypeScript** - Type safety
- **Material-UI v5** - Component library
- **Redux Toolkit** - State management
- **Socket.io-client** - Real-time updates
- **React Query** - Data fetching
- **React Router v6** - Navigation

### Infrastructure
- **Docker** - Containerization
- **PostgreSQL** - Primary database
- **Redis** - Cache/queue
- **Nginx** - Reverse proxy
- **Kubernetes** - Orchestration

## 📁 Project Structure

```
enterprise-osint-flask/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── api/
│   │   │   ├── auth.py
│   │   │   ├── investigations.py
│   │   │   ├── reports.py
│   │   │   └── mcp.py
│   │   ├── models/
│   │   │   ├── user.py
│   │   │   ├── investigation.py
│   │   │   └── report.py
│   │   ├── services/
│   │   │   ├── osint.py
│   │   │   ├── mcp_client.py
│   │   │   └── pdf_generator.py
│   │   ├── tasks/
│   │   │   ├── investigation.py
│   │   │   └── report.py
│   │   └── utils/
│   ├── config.py
│   ├── requirements.txt
│   └── wsgi.py
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   ├── store/
│   │   └── App.tsx
│   ├── package.json
│   └── tsconfig.json
│
├── docker/
│   ├── docker-compose.yml
│   ├── Dockerfile.backend
│   └── Dockerfile.frontend
│
└── docs/
    ├── API.md
    ├── DEPLOYMENT.md
    └── DEVELOPMENT.md
```

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Node.js 18+
- Docker & Docker Compose
- PostgreSQL 14+
- Redis 7+

### Development Setup

1. **Clone and setup:**
```bash
git clone <repository>
cd enterprise-osint-flask
```

2. **Backend setup:**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. **Frontend setup:**
```bash
cd frontend
npm install
```

4. **Start services:**
```bash
# Start PostgreSQL and Redis
docker-compose up -d postgres redis

# Start backend
cd backend
flask run

# Start Celery worker
celery -A app.celery worker --loglevel=info

# Start frontend
cd frontend
npm start
```

## 🔐 Authentication & Security

- JWT token-based authentication
- Role-based access control (RBAC)
- API rate limiting
- CORS configuration
- Security headers (CSP, HSTS, etc.)
- Input validation and sanitization

## 🔍 Core Features

### Investigation Management
- Create and track OSINT investigations
- Real-time progress updates via WebSocket
- Background processing for long-running tasks
- Investigation history and audit logs

### MCP Server Integration
- Dynamic MCP server discovery
- Tool execution and monitoring
- Result aggregation and analysis
- Error handling and retry logic

### Report Generation
- Professional PDF reports
- Multiple export formats (PDF, JSON, CSV)
- Scheduled report generation
- Report expiration and security

### API Endpoints
```
POST   /api/auth/login
POST   /api/auth/refresh
GET    /api/investigations
POST   /api/investigations
GET    /api/investigations/{id}
DELETE /api/investigations/{id}
GET    /api/investigations/{id}/report
POST   /api/investigations/{id}/report
GET    /api/mcp/servers
GET    /api/mcp/servers/{id}/tools
POST   /api/mcp/execute
```

## 🐳 Docker Deployment

```bash
# Build and run all services
docker-compose up --build

# Access the application
# Frontend: http://localhost:3000
# Backend API: http://localhost:5000
# API Docs: http://localhost:5000/api/docs
```

## 🌐 Production Deployment

See [DEPLOYMENT.md](docs/DEPLOYMENT.md) for detailed production deployment instructions including:
- Kubernetes manifests
- Helm charts
- Environment configuration
- Security hardening
- Monitoring setup

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔗 Links

- [API Documentation](docs/API.md)
- [Development Guide](docs/DEVELOPMENT.md)
- [Deployment Guide](docs/DEPLOYMENT.md)