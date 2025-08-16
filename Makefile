# Makefile for Enterprise OSINT Platform
# Automates common development and deployment tasks

.PHONY: help setup deploy rebuild-backend rebuild-frontend rebuild-all port-forward status clean logs

# Default target
help:
	@echo "Enterprise OSINT Platform - Development Commands"
	@echo "==============================================="
	@echo ""
	@echo "Setup & Deployment:"
	@echo "  make setup          - Initialize namespace and secrets"
	@echo "  make deploy         - Deploy all components to Kubernetes"
	@echo ""
	@echo "Development:"
	@echo "  make rebuild-backend  - Rebuild and deploy backend with port forwarding"
	@echo "  make rebuild-frontend - Rebuild and deploy frontend with port forwarding"
	@echo "  make rebuild-all      - Rebuild both backend and frontend"
	@echo ""
	@echo "Operations:"
	@echo "  make port-forward   - Ensure port forwarding is active"
	@echo "  make status         - Check system status"
	@echo "  make logs           - Tail backend logs"
	@echo "  make clean          - Clean up port forwards"
	@echo ""
	@echo "Quick Start:"
	@echo "  make deploy && make port-forward"
	@echo ""

# Setup namespace and base resources
setup:
	@echo "🔧 Setting up OSINT platform namespace..."
	kubectl create namespace osint-platform --dry-run=client -o yaml | kubectl apply -f -
	@echo "✅ Namespace ready"

# Deploy all components
deploy:
	@echo "🚀 Deploying OSINT platform to Kubernetes..."
	kubectl apply -f k8s/postgresql-deployment.yaml
	kubectl apply -f k8s/vault-deployment.yaml
	kubectl apply -f k8s/enhanced-mcp-deployments.yaml
	kubectl apply -f k8s/simple-backend-deployment.yaml
	kubectl apply -f k8s/simple-frontend-deployment.yaml
	@echo "✅ All components deployed"
	@echo ""
	@echo "Run 'make port-forward' to access the platform"

# Rebuild and deploy backend
rebuild-backend:
	@echo "🔨 Rebuilding backend..."
	docker build -t osint-platform/simple-backend:latest simple-backend/
	@echo "📦 Updating backend deployment..."
	kubectl set image deployment/osint-backend backend=osint-platform/simple-backend:latest -n osint-platform
	kubectl rollout status deployment/osint-backend -n osint-platform
	@echo "✅ Backend rebuilt and deployed"
	@echo "🔌 Restarting port forwards..."
	@./ensure-port-forwards.sh

# Rebuild and deploy frontend
rebuild-frontend:
	@echo "🔨 Rebuilding frontend..."
	docker build -t osint-platform/simple-frontend:latest simple-frontend/
	@echo "📦 Updating frontend deployment..."
	kubectl set image deployment/osint-simple-frontend frontend=osint-platform/simple-frontend:latest -n osint-platform
	kubectl rollout status deployment/osint-simple-frontend -n osint-platform
	@echo "✅ Frontend rebuilt and deployed"
	@echo "🔌 Restarting port forwards..."
	@./ensure-port-forwards.sh

# Rebuild everything
rebuild-all: rebuild-backend rebuild-frontend
	@echo "✅ All components rebuilt"

# Ensure port forwarding is active
port-forward:
	@./ensure-port-forwards.sh

# Check system status
status:
	@echo "📊 OSINT Platform Status"
	@echo "========================"
	@echo ""
	@echo "Pods:"
	@kubectl get pods -n osint-platform | grep -E "(backend|frontend|mcp)" || echo "No pods found"
	@echo ""
	@echo "Services:"
	@kubectl get svc -n osint-platform | grep -E "(backend|frontend)" || echo "No services found"
	@echo ""
	@echo "Port Forwards:"
	@ps aux | grep -E "kubectl port-forward.*(5000|8080)" | grep -v grep || echo "No active port forwards"
	@echo ""
	@echo "Testing connectivity..."
	@curl -s http://localhost:5000/health 2>/dev/null | grep -q "healthy" && echo "✅ Backend: OK" || echo "❌ Backend: Not accessible"
	@curl -s http://localhost:8080/health.html 2>/dev/null | grep -q "OK" && echo "✅ Frontend: OK" || echo "❌ Frontend: Not accessible"

# Clean up port forwards
clean:
	@echo "🧹 Cleaning up port forwards..."
	@pkill -f "kubectl port-forward.*5000" 2>/dev/null || true
	@pkill -f "kubectl port-forward.*8080" 2>/dev/null || true
	@echo "✅ Port forwards cleaned up"

# View logs
logs:
	kubectl logs -f -n osint-platform -l app=osint-backend --tail=50

# Quick development rebuild with auto port-forward
dev-backend:
	@echo "🚀 Quick backend development rebuild..."
	docker build -t osint-platform/simple-backend:dev simple-backend/
	kubectl set image deployment/osint-backend backend=osint-platform/simple-backend:dev -n osint-platform
	kubectl rollout status deployment/osint-backend -n osint-platform --timeout=60s
	@sleep 2
	@make port-forward

dev-frontend:
	@echo "🚀 Quick frontend development rebuild..."
	docker build -t osint-platform/simple-frontend:dev simple-frontend/
	kubectl set image deployment/osint-simple-frontend frontend=osint-platform/simple-frontend:dev -n osint-platform
	kubectl rollout status deployment/osint-simple-frontend -n osint-platform --timeout=60s
	@sleep 2
	@make port-forward