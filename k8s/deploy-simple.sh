#!/bin/bash

echo "=== Enterprise OSINT Platform - Simple Deployment ==="
echo ""

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "Error: kubectl is not installed or not in PATH"
    exit 1
fi

# Check current context
echo "Current Kubernetes context:"
kubectl config current-context
echo ""

read -p "Do you want to continue with this context? (y/n) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled"
    exit 1
fi

echo ""
echo "=== Creating namespace ==="
kubectl apply -f namespace.yaml

echo ""
echo "=== Creating secrets ==="
echo "WARNING: Remember to update the API keys in secrets.yaml before production deployment!"
kubectl apply -f secrets.yaml

echo ""
echo "=== Deploying PostgreSQL ==="
kubectl apply -f postgresql-deployment.yaml

echo ""
echo "=== Deploying Redis ==="
kubectl apply -f redis-deployment.yaml

echo ""
echo "=== Deploying Vault ==="
kubectl apply -f vault-simple.yaml

echo ""
echo "=== Waiting for infrastructure services to be ready ==="
echo "Waiting for PostgreSQL..."
kubectl wait --for=condition=ready pod -l app=postgresql -n osint-platform --timeout=120s
echo "Waiting for Redis..."
kubectl wait --for=condition=ready pod -l app=redis -n osint-platform --timeout=60s
echo "Waiting for Vault..."
kubectl wait --for=condition=ready pod -l app=vault -n osint-platform --timeout=60s

echo ""
echo "=== Deploying MCP Servers ==="
kubectl apply -f mcp-deployments.yaml

echo ""
echo "=== Deploying Backend ==="
kubectl apply -f simple-backend-deployment.yaml

echo ""
echo "=== Deploying Frontend ==="
kubectl apply -f simple-frontend-deployment.yaml

echo ""
echo "=== Deployment Status ==="
kubectl get all -n osint-platform

echo ""
echo "=== Next Steps ==="
echo "1. Build Docker images if not already done:"
echo "   - docker build -t osint-platform/backend:local simple-backend/"
echo "   - docker build -t osint-platform/simple-frontend:local simple-frontend/"
echo "   - docker build -t osint-platform/mcp-social-media:local mcp-servers/social-media/"
echo "   - docker build -t osint-platform/mcp-infrastructure:local mcp-servers/infrastructure/"
echo "   - docker build -t osint-platform/mcp-threat-intel:local mcp-servers/threat-intel/"
echo ""
echo "2. Port forward to access services:"
echo "   - kubectl port-forward -n osint-platform svc/osint-simple-frontend 8080:80"
echo "   - kubectl port-forward -n osint-platform svc/osint-backend 5000:5000"
echo ""
echo "3. Update API keys in secrets.yaml and reapply:"
echo "   - kubectl apply -f secrets.yaml"
echo ""
echo "=== Deployment Complete ===" 