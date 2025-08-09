# Enterprise OSINT Platform - Architecture Overview

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     React Frontend (SPA)                      │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │   Auth UI   │  │ Investigation │  │  Real-time Updates│  │
│  │   (JWT)     │  │      UI       │  │   (WebSocket)     │  │
│  └─────────────┘  └──────────────┘  └───────────────────┘  │
└───────────────────────────┬─────────────────────────────────┘
                           │ HTTPS
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                     Nginx (Reverse Proxy)                    │
│              SSL Termination, Load Balancing                 │
└───────────────────────────┬─────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Flask Backend (API)                       │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │   REST API  │  │  WebSocket   │  │  Background Tasks │  │
│  │  Endpoints  │  │   Server     │  │    (Celery)       │  │
│  └─────────────┘  └──────────────┘  └───────────────────┘  │
└───────────────────────────┬─────────────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  PostgreSQL  │  │    Redis     │  │ MCP Servers  │
│  (Primary DB)│  │ (Cache/Queue)│  │(OSINT Tools) │
└──────────────┘  └──────────────┘  └──────────────┘
```

## 🔧 Technology Stack Details

### Frontend (React + TypeScript)

**Core Technologies:**
- React 18 with TypeScript for type safety
- Material-UI v5 for professional UI components
- Redux Toolkit for state management
- React Query for server state and caching
- Socket.io-client for real-time updates
- Formik + Yup for form handling and validation

**Key Features:**
- Single Page Application (SPA) architecture
- JWT-based authentication with refresh tokens
- Real-time investigation progress via WebSocket
- Responsive design for mobile and desktop
- Dark/light theme support
- Internationalization ready

### Backend (Flask + Python)

**Core Technologies:**
- Flask 3.0 with async support
- SQLAlchemy ORM with PostgreSQL
- Celery for distributed task processing
- Redis for caching and message broker
- Flask-SocketIO for WebSocket support
- JWT authentication with refresh tokens

**Key Features:**
- RESTful API design
- Async investigation processing
- Real-time progress updates
- Rate limiting and API throttling
- Comprehensive error handling
- API versioning support

## 📊 Data Flow

### Investigation Workflow

1. **User initiates investigation:**
   ```
   Frontend → POST /api/investigations → Flask API
   ```

2. **API creates investigation record:**
   ```
   Flask → PostgreSQL (store investigation)
   Flask → Celery (queue background task)
   ```

3. **Background processing:**
   ```
   Celery Worker → MCP Servers (OSINT tools)
   Celery Worker → Redis (progress updates)
   Celery Worker → WebSocket (real-time updates)
   ```

4. **Real-time updates:**
   ```
   WebSocket → Frontend (progress/status)
   Frontend → Redux (update state)
   Frontend → UI (render progress)
   ```

5. **Results delivery:**
   ```
   Celery Worker → PostgreSQL (store results)
   Celery Worker → WebSocket (completion notification)
   Frontend → GET /api/investigations/{id}/report
   ```

## 🔐 Security Architecture

### Authentication Flow
```
1. Login: Frontend → POST /api/auth/login → JWT tokens
2. Request: Frontend → API (Bearer token in header)
3. Refresh: Frontend → POST /api/auth/refresh → New access token
4. Logout: Frontend → Remove tokens (client-side)
```

### Security Layers
- **Network**: SSL/TLS encryption, CORS configuration
- **Application**: JWT authentication, RBAC authorization
- **API**: Rate limiting, input validation, SQL injection prevention
- **Data**: Encryption at rest, secure password hashing (bcrypt)

## 🚀 Deployment Architecture

### Development
```
- Frontend: webpack dev server (port 3000)
- Backend: Flask development server (port 5000)
- PostgreSQL: Docker container
- Redis: Docker container
```

### Production (Kubernetes)
```
┌─────────────────────────────────────────┐
│          Kubernetes Cluster             │
│                                         │
│  ┌─────────────┐  ┌─────────────┐     │
│  │   Frontend   │  │   Backend    │     │
│  │    Pods      │  │     Pods     │     │
│  └─────────────┘  └─────────────┘     │
│                                         │
│  ┌─────────────┐  ┌─────────────┐     │
│  │   Celery     │  │     MCP      │     │
│  │   Workers    │  │   Servers    │     │
│  └─────────────┘  └─────────────┘     │
│                                         │
│  ┌─────────────┐  ┌─────────────┐     │
│  │  PostgreSQL  │  │    Redis     │     │
│  │  StatefulSet │  │  Deployment  │     │
│  └─────────────┘  └─────────────┘     │
└─────────────────────────────────────────┘
```

## 📈 Scalability Considerations

### Horizontal Scaling
- **Frontend**: CDN distribution, multiple pod replicas
- **Backend**: Load balanced API pods, stateless design
- **Workers**: Auto-scaling Celery workers based on queue depth
- **Database**: Read replicas, connection pooling

### Performance Optimization
- **Caching**: Redis for API responses, investigation results
- **Async Processing**: Non-blocking I/O for OSINT operations
- **Database**: Indexed queries, query optimization
- **Frontend**: Code splitting, lazy loading, memoization

## 🔄 API Design

### RESTful Endpoints
```
Authentication:
POST   /api/auth/register
POST   /api/auth/login
POST   /api/auth/refresh
POST   /api/auth/logout
GET    /api/auth/me
PUT    /api/auth/me

Investigations:
GET    /api/investigations
POST   /api/investigations
GET    /api/investigations/{id}
PUT    /api/investigations/{id}
DELETE /api/investigations/{id}
GET    /api/investigations/{id}/logs
POST   /api/investigations/{id}/cancel

Reports:
GET    /api/investigations/{id}/report
POST   /api/investigations/{id}/report
GET    /api/reports
GET    /api/reports/{id}/download

MCP Integration:
GET    /api/mcp/servers
GET    /api/mcp/servers/{id}/status
GET    /api/mcp/servers/{id}/tools
POST   /api/mcp/execute
```

### WebSocket Events
```
Client → Server:
- subscribe_investigation: {investigation_id}
- unsubscribe_investigation: {investigation_id}

Server → Client:
- investigation_progress: {id, progress, step}
- investigation_completed: {id, results}
- investigation_failed: {id, error}
- investigation_log: {id, message, level}
```

## 🏗️ Development Workflow

### Local Development
```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
flask db upgrade
flask run

# Frontend
cd frontend
npm install
npm start

# Background Tasks
celery -A app.celery worker --loglevel=info

# Services
docker-compose up postgres redis
```

### Testing
```bash
# Backend tests
pytest backend/tests --cov=app

# Frontend tests
npm test -- --coverage

# E2E tests
npm run cypress:run
```

### CI/CD Pipeline
1. **Code Push** → GitHub
2. **CI Tests** → GitHub Actions
3. **Build Images** → Docker Hub
4. **Deploy** → Kubernetes (ArgoCD)
5. **Monitor** → Prometheus/Grafana

## 📊 Monitoring & Observability

### Metrics
- **Application**: Response times, error rates, throughput
- **Infrastructure**: CPU, memory, disk usage
- **Business**: Investigations/day, report generation time

### Logging
- **Structured Logging**: JSON format for easy parsing
- **Centralized**: ELK stack (Elasticsearch, Logstash, Kibana)
- **Correlation**: Request ID tracking across services

### Alerting
- **Prometheus**: Metric-based alerts
- **PagerDuty**: Critical incident management
- **Slack**: Non-critical notifications

This architecture provides a solid foundation for an enterprise-grade OSINT platform with scalability, security, and maintainability in mind.