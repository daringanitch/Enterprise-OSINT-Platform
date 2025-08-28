# Deployment Instructions for Enterprise OSINT Platform

## Option 1: Enable Kubernetes in Docker Desktop (Recommended)

### Enable Kubernetes:
1. Open Docker Desktop
2. Go to Settings/Preferences → Kubernetes
3. Check "Enable Kubernetes"
4. Click "Apply & Restart"
5. Wait for Kubernetes to start (green icon)

### Once Kubernetes is Running:
```bash
# Verify Kubernetes is working
kubectl cluster-info

# Create namespace
kubectl create namespace osint-platform

# Deploy the platform
kubectl apply -f k8s/postgresql-deployment.yaml
kubectl apply -f k8s/simple-backend-deployment.yaml  
kubectl apply -f k8s/simple-frontend-deployment.yaml

# Check deployment status
kubectl get pods -n osint-platform
```

## Option 2: Docker Compose Deployment (Alternative)

If you prefer not to use Kubernetes, here's a docker-compose setup:

### Create docker-compose.yml:
```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: osint_audit
      POSTGRES_USER: osint_user
      POSTGRES_PASSWORD: osint_secure_pass
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  backend:
    build: ./simple-backend
    environment:
      POSTGRES_URL: postgresql://osint_user:osint_secure_pass@postgres:5432/osint_audit
      JWT_SECRET_KEY: ${JWT_SECRET_KEY}
      FLASK_ENV: development
    ports:
      - "5000:5000"
    depends_on:
      - postgres

  frontend:
    build: ./simple-frontend
    ports:
      - "8080:80"
    depends_on:
      - backend

volumes:
  postgres_data:
```

### Run with Docker Compose:
```bash
# Load environment variables
export $(cat .env | xargs)

# Start services
docker-compose up -d

# Check logs
docker-compose logs -f
```

## Option 3: Local Development Mode

For quick testing without containers:

### 1. Start PostgreSQL (if installed locally):
```bash
# macOS with Homebrew
brew services start postgresql
createdb osint_audit
```

### 2. Run Backend:
```bash
cd simple-backend
pip install -r requirements.txt
export $(cat ../.env | xargs)
python app.py
```

### 3. Run Frontend:
```bash
cd simple-frontend
# Serve static files
python -m http.server 8080
```

## Checking Deployment Status

### For Kubernetes:
```bash
# Watch pods starting up
kubectl get pods -n osint-platform -w

# Check logs if issues
kubectl logs -n osint-platform -l app=osint-backend

# Port forward to access
kubectl port-forward -n osint-platform svc/osint-simple-frontend 8080:80
kubectl port-forward -n osint-platform svc/osint-backend 5000:5000
```

### For Docker Compose:
```bash
# Check status
docker-compose ps

# View logs
docker-compose logs backend
docker-compose logs frontend
```

## Access the Platform

Once deployed, access at:
- Frontend: http://localhost:8080
- Backend API: http://localhost:5000
- Login: admin / admin123

## Troubleshooting

### Kubernetes Not Starting:
- Ensure Docker Desktop has enough resources (Settings → Resources)
- Recommended: 4GB RAM, 2 CPUs minimum
- Reset Kubernetes cluster in Docker Desktop settings

### Database Connection Issues:
- Check PostgreSQL is running
- Verify POSTGRES_URL in environment
- Check network connectivity between services

### Port Already in Use:
```bash
# Find what's using port 8080
lsof -i :8080

# Kill process or use different port
```