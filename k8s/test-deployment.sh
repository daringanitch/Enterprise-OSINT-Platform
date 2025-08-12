#!/bin/bash

echo "=== Testing Enterprise OSINT Platform Deployment ==="
echo ""

NAMESPACE="osint-platform"

# Function to check pod status
check_pods() {
    echo "=== Pod Status ==="
    kubectl get pods -n $NAMESPACE
    echo ""
}

# Function to check service endpoints
check_services() {
    echo "=== Service Endpoints ==="
    kubectl get svc -n $NAMESPACE
    echo ""
}

# Function to test service connectivity
test_service() {
    local service=$1
    local port=$2
    local path=${3:-"/"}
    
    echo "Testing $service on port $port..."
    
    # Create a test pod
    kubectl run test-curl-$RANDOM -n $NAMESPACE --rm -i --restart=Never --image=curlimages/curl -- \
        curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" http://$service:$port$path || \
        echo "Failed to connect to $service"
}

# Run checks
check_pods
check_services

echo "=== Testing Service Connectivity ==="
echo ""

# Test backend
test_service "osint-backend" "5000" "/api/health"

# Test Redis
echo "Testing Redis..."
kubectl run test-redis-$RANDOM -n $NAMESPACE --rm -i --restart=Never --image=redis:7-alpine -- \
    redis-cli -h redis ping || echo "Failed to connect to Redis"

# Test PostgreSQL
echo "Testing PostgreSQL..."
kubectl run test-psql-$RANDOM -n $NAMESPACE --rm -i --restart=Never --image=postgres:15-alpine -- \
    psql -h postgresql -U postgres -c "SELECT 1" || echo "Failed to connect to PostgreSQL"

# Test Vault
test_service "vault" "8200" "/v1/sys/health"

echo ""
echo "=== Port Forwarding Commands ==="
echo "To access the services locally, use these commands:"
echo ""
echo "Frontend: kubectl port-forward -n $NAMESPACE svc/osint-simple-frontend 8080:80"
echo "Backend:  kubectl port-forward -n $NAMESPACE svc/osint-backend 5000:5000"
echo "Vault UI: kubectl port-forward -n $NAMESPACE svc/vault 8200:8200"
echo ""
echo "=== Test Complete ===" 