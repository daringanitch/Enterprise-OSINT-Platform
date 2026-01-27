#\!/bin/bash
# Script to ensure port forwarding is always running for frontend and backend

echo "🔧 Ensuring port forwards are active for OSINT platform..."

# Function to check if port forward is running
check_port_forward() {
    local port=$1
    if lsof -i :$port | grep -q kubectl; then
        return 0
    else
        return 1
    fi
}

# Function to kill existing port forwards
kill_port_forwards() {
    echo "🛑 Cleaning up existing port forwards..."
    pkill -f "kubectl port-forward.*5000" 2>/dev/null || true
    pkill -f "kubectl port-forward.*8080" 2>/dev/null || true
    sleep 2
}

# Function to start port forward
start_port_forward() {
    local service=$1
    local local_port=$2
    local remote_port=$3
    
    echo "🚀 Starting port forward for $service ($local_port -> $remote_port)..."
    kubectl port-forward -n osint-platform svc/$service $local_port:$remote_port >/dev/null 2>&1 &
    
    # Wait for port forward to establish
    sleep 3
    
    # Verify it's working
    if check_port_forward $local_port; then
        echo "✅ Port forward for $service is active on port $local_port"
    else
        echo "❌ Failed to start port forward for $service"
        return 1
    fi
}

# Function to test connectivity
test_connectivity() {
    echo ""
    echo "🧪 Testing connectivity..."
    
    # Test backend
    if curl -s http://localhost:5000/health | grep -q "healthy"; then
        echo "✅ Backend is accessible at http://localhost:5000"
    else
        echo "❌ Backend is NOT accessible"
    fi
    
    # Test frontend
    if curl -s http://localhost:8080/health.html | grep -q "Frontend Health OK"; then
        echo "✅ Frontend is accessible at http://localhost:8080"
    else
        echo "❌ Frontend is NOT accessible"
    fi
}

# Main execution
echo "═══════════════════════════════════════════════════════════"
echo "  OSINT Platform Port Forward Manager"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Kill existing port forwards
kill_port_forwards

# Start backend port forward
start_port_forward "osint-backend" 5000 5000

# Start frontend port forward
start_port_forward "osint-simple-frontend" 8080 80

# Test connectivity
test_connectivity

echo ""
echo "🎉 Port forwarding is active\!"
echo ""
echo "📌 Access points:"
echo "   Frontend: http://localhost:8080"
echo "   Backend:  http://localhost:5000"
echo ""
echo "📝 Login credentials:"
echo "   Username: admin"
echo "   Password: admin123"
echo ""
EOF < /dev/null