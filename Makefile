# Enterprise OSINT Platform Makefile
# Common operations for development and deployment

.PHONY: help setup install run stop clean test lint format build deploy logs

# Default target
help:
	@echo "Enterprise OSINT Platform - Available Commands"
	@echo "============================================="
	@echo "  make setup      - Initial project setup"
	@echo "  make install    - Install dependencies"
	@echo "  make run        - Run with docker-compose"
	@echo "  make run-dev    - Run in development mode"
	@echo "  make stop       - Stop all services"
	@echo "  make clean      - Clean up containers and volumes"
	@echo "  make test       - Run tests"
	@echo "  make lint       - Run code linting"
	@echo "  make format     - Format code"
	@echo "  make build      - Build Docker images"
	@echo "  make deploy     - Deploy to Kubernetes"
	@echo "  make logs       - View application logs"
	@echo "  make status     - Check system status"

# Initial setup
setup:
	@echo "🚀 Running initial setup..."
	@./setup.sh

# Install dependencies
install:
	@echo "📦 Installing dependencies..."
	@cd simple-backend && \
		python3 -m venv venv && \
		. venv/bin/activate && \
		pip install -r requirements.txt

# Run with docker-compose
run:
	@echo "🚀 Starting services with docker-compose..."
	@docker-compose up -d
	@echo "✅ Services started!"
	@echo "   Frontend: http://localhost:8080"
	@echo "   Backend: http://localhost:5000"
	@echo "   Vault: http://localhost:8200"
	@echo "   PostgreSQL: localhost:5432"

# Run in development mode
run-dev:
	@echo "🧪 Starting in development mode..."
	@cd simple-backend && \
		. venv/bin/activate && \
		python app.py &
	@cd simple-frontend && \
		python3 -m http.server 8080 &
	@echo "✅ Development servers started!"

# Stop all services
stop:
	@echo "🛑 Stopping services..."
	@docker-compose down

# Clean up everything
clean:
	@echo "🧹 Cleaning up..."
	@docker-compose down -v
	@rm -rf simple-backend/venv
	@rm -rf simple-backend/__pycache__
	@rm -rf simple-backend/*.pyc
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@echo "✅ Cleanup complete!"

# Run tests
test:
	@echo "🧪 Running tests..."
	@cd simple-backend && \
		. venv/bin/activate && \
		python -m pytest tests/ -v

# Run linting
lint:
	@echo "🔍 Running code linting..."
	@cd simple-backend && \
		. venv/bin/activate && \
		flake8 . --exclude=venv
	@echo "✅ Linting complete!"

# Format code
format:
	@echo "✨ Formatting code..."
	@cd simple-backend && \
		. venv/bin/activate && \
		black . --exclude=venv
	@echo "✅ Code formatted!"

# Build Docker images
build:
	@echo "🏗️  Building Docker images..."
	@docker-compose build
	@echo "✅ Build complete!"

# Deploy to Kubernetes
deploy:
	@echo "☸️  Deploying to Kubernetes..."
	@kubectl apply -f k8s/namespace.yaml
	@kubectl apply -f k8s/postgresql-deployment.yaml
	@kubectl apply -f k8s/vault-deployment.yaml
	@echo "⏳ Waiting for database and vault to be ready..."
	@sleep 30
	@kubectl apply -f k8s/
	@echo "✅ Deployment complete!"
	@kubectl get pods -n osint-platform

# View logs
logs:
	@echo "📋 Viewing application logs..."
	@docker-compose logs -f backend

# Check system status
status:
	@echo "📊 Checking system status..."
	@curl -s http://localhost:5000/api/system/status | jq . || echo "Backend not accessible"
	@echo ""
	@echo "🐳 Docker container status:"
	@docker-compose ps

# Database operations
db-shell:
	@echo "🗄️  Connecting to PostgreSQL..."
	@docker exec -it osint-postgresql psql -U postgres -d osint_audit

db-backup:
	@echo "💾 Backing up database..."
	@docker exec osint-postgresql pg_dump -U postgres osint_audit > backup_$(shell date +%Y%m%d_%H%M%S).sql
	@echo "✅ Backup complete!"

db-restore:
	@echo "📥 Restoring database..."
	@echo "Usage: make db-restore FILE=backup.sql"
	@docker exec -i osint-postgresql psql -U postgres -d osint_audit < $(FILE)

# API monitoring
api-status:
	@echo "🔌 Checking API status..."
	@curl -s http://localhost:5000/api/monitoring/apis | jq . || echo "API monitoring not accessible"

api-check:
	@echo "🔍 Triggering API health check..."
	@curl -X POST http://localhost:5000/api/monitoring/apis/check | jq .

# Development helpers
shell-backend:
	@docker exec -it osint-backend /bin/sh

shell-frontend:
	@docker exec -it osint-frontend /bin/sh

# Port forwarding for Kubernetes
port-forward:
	@echo "🔌 Setting up port forwarding..."
	@kubectl port-forward -n osint-platform svc/osint-backend 5000:5000 &
	@kubectl port-forward -n osint-platform svc/osint-frontend 8080:80 &
	@echo "✅ Port forwarding established!"