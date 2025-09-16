#!/bin/bash

# Deploy Demo/Production Mode System
# This script sets up the Enterprise OSINT Platform with demo/production mode capabilities

set -e

echo "🚀 Deploying Enterprise OSINT Platform with Demo/Production Mode Support"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    print_error "kubectl is required but not installed"
    exit 1
fi

# Check if Docker is running
if ! docker info &> /dev/null; then
    print_error "Docker is required and must be running"
    exit 1
fi

print_status "Checking Kubernetes cluster..."

# Create namespace if it doesn't exist
kubectl create namespace osint-platform --dry-run=client -o yaml | kubectl apply -f -

print_status "📁 Deploying configuration files..."

# Deploy mode configuration
kubectl apply -f k8s/mode-config-configmap.yaml

# Deploy API keys secret template (empty by default for demo mode)
kubectl apply -f k8s/api-keys-secret-template.yaml

print_status "🐳 Building Docker images..."

# Build backend with demo/production mode support
docker build -t osint-platform/simple-backend:latest -f simple-backend/Dockerfile simple-backend/

# Build frontend with mode toggle
docker build -t osint-platform/simple-frontend:latest -f simple-frontend/Dockerfile simple-frontend/

print_status "🚀 Deploying services..."

# Deploy PostgreSQL if not already deployed
if ! kubectl get deployment osint-platform-postgresql -n osint-platform &> /dev/null; then
    print_status "Deploying PostgreSQL..."
    kubectl apply -f k8s/postgresql-deployment.yaml
fi

# Deploy Redis if not already deployed  
if ! kubectl get deployment osint-platform-redis-master -n osint-platform &> /dev/null; then
    print_status "Deploying Redis..."
    kubectl apply -f k8s/redis-deployment.yaml 2>/dev/null || print_warning "Redis deployment file not found, skipping..."
fi

# Deploy backend with mode support
kubectl apply -f k8s/simple-backend-deployment.yaml

# Deploy frontend with mode toggle
kubectl apply -f k8s/simple-frontend-deployment.yaml

# Deploy MCP servers (optional)
for mcp_file in k8s/mcp-*.yaml k8s/*mcp*.yaml; do
    if [ -f "$mcp_file" ]; then
        print_status "Deploying MCP server: $(basename $mcp_file)"
        kubectl apply -f "$mcp_file" || print_warning "Failed to deploy $mcp_file"
    fi
done

print_status "⏳ Waiting for deployments to be ready..."

# Wait for deployments
kubectl rollout status deployment/osint-backend -n osint-platform --timeout=300s
kubectl rollout status deployment/osint-simple-frontend -n osint-platform --timeout=300s

print_status "🔍 Checking deployment status..."

# Check pod status
kubectl get pods -n osint-platform -l app=osint-backend
kubectl get pods -n osint-platform -l app=osint-frontend

print_status "🌐 Setting up port forwarding..."

# Kill existing port forwards
pkill -f "kubectl port-forward" 2>/dev/null || true

# Start port forwarding in background
kubectl port-forward -n osint-platform svc/osint-simple-frontend 8080:80 &
kubectl port-forward -n osint-platform svc/osint-backend 5000:5000 &

# Give port forwarding time to establish
sleep 3

print_status "✅ Deployment complete!"

echo ""
echo "🎯 Access URLs:"
echo "   Frontend (with Mode Toggle): http://localhost:8080"
echo "   Backend API:                 http://localhost:5000"
echo ""
echo "🔧 Default Configuration:"
echo "   • Mode: Demo (no API keys required)"
echo "   • Demo Data: 5 sample investigations"
echo "   • Auto-fallback: Enabled"
echo ""
echo "📋 Available API Endpoints:"
echo "   • GET  /api/system/mode        - Get current mode status"
echo "   • POST /api/system/mode        - Switch between demo/production"
echo "   • GET  /api/system/api-keys    - Check API key availability"
echo "   • GET  /api/investigations     - Get investigations (demo or real data)"
echo ""
echo "🔑 To Add Production API Keys:"
echo "   1. Create API keys secret:"
echo "      kubectl create secret generic osint-api-keys \\"
echo "        --from-literal=OPENAI_API_KEY='your-key' \\"
echo "        --from-literal=VIRUSTOTAL_API_KEY='your-key' \\"
echo "        -n osint-platform"
echo ""
echo "   2. Toggle to production mode via UI or API"
echo ""
echo "🧪 Testing:"
echo "   1. Open http://localhost:8080"
echo "   2. Login: admin / admin123"
echo "   3. Use mode toggle in top-right corner"
echo "   4. Create investigations and see demo vs real data"
echo ""

# Show system status
print_status "📊 Current System Status:"
kubectl get all -n osint-platform | head -20

echo ""
echo "🎉 Enterprise OSINT Platform with Demo/Production Mode is ready!"
echo "   Toggle between modes using the UI switch or API endpoints."