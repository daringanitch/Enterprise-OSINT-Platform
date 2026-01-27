#!/bin/bash

echo "🔧 Setting up all port forwards for OSINT Platform testing..."
echo "═══════════════════════════════════════════════════════════"

# Kill existing port forwards to avoid conflicts
echo "🛑 Cleaning up existing port forwards..."
pkill -f "kubectl port-forward" || true
sleep 2

# Start all necessary port forwards
echo "🚀 Starting port forwards..."

# Backend API (using 5001 to avoid macOS Control Center on 5000)
kubectl port-forward -n osint-platform svc/osint-backend 5001:5000 > /dev/null 2>&1 &
echo "✅ Backend API: http://localhost:5001"

# Frontend
kubectl port-forward -n osint-platform svc/osint-simple-frontend 8080:80 > /dev/null 2>&1 &
echo "✅ Frontend: http://localhost:8080"

# MCP Servers (for direct testing if needed)
kubectl port-forward -n osint-platform svc/mcp-infrastructure-enhanced 8021:8021 > /dev/null 2>&1 &
echo "✅ Infrastructure MCP: http://localhost:8021"

kubectl port-forward -n osint-platform svc/mcp-social-enhanced 8010:8010 > /dev/null 2>&1 &
echo "✅ Social Media MCP: http://localhost:8010"

kubectl port-forward -n osint-platform svc/mcp-threat-enhanced 8020:8020 > /dev/null 2>&1 &
echo "✅ Threat Intel MCP: http://localhost:8020"

kubectl port-forward -n osint-platform svc/mcp-financial-enhanced 8040:8040 > /dev/null 2>&1 &
echo "✅ Financial MCP: http://localhost:8040"

kubectl port-forward -n osint-platform svc/mcp-technical-enhanced 8050:8050 > /dev/null 2>&1 &
echo "✅ Technical MCP: http://localhost:8050"

# PostgreSQL (for debugging if needed)
kubectl port-forward -n osint-platform svc/postgresql 5432:5432 > /dev/null 2>&1 &
echo "✅ PostgreSQL: localhost:5432"

echo ""
echo "⏳ Waiting for services to be ready..."
sleep 5

# Test connectivity
echo ""
echo "🧪 Testing connectivity..."
echo "─────────────────────────"

# Test Backend
if curl -s -f http://localhost:5001/health > /dev/null 2>&1; then
    echo "✅ Backend API is accessible"
else
    echo "❌ Backend API is NOT accessible"
fi

# Test Frontend
if curl -s -f http://localhost:8080 > /dev/null 2>&1; then
    echo "✅ Frontend is accessible"
else
    echo "❌ Frontend is NOT accessible"
fi

# Test MCPs
for mcp in "8021:Infrastructure" "8010:Social" "8020:Threat" "8040:Financial" "8050:Technical"; do
    port=$(echo $mcp | cut -d: -f1)
    name=$(echo $mcp | cut -d: -f2)
    if curl -s -f http://localhost:$port/health > /dev/null 2>&1; then
        echo "✅ $name MCP is accessible"
    else
        echo "❌ $name MCP is NOT accessible"
    fi
done

echo ""
echo "📊 API Endpoints Summary:"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "🌐 Frontend Access:"
echo "   URL: http://localhost:8080"
echo "   Login: admin / admin123"
echo ""
echo "🔌 Backend API Endpoints:"
echo "   Base URL: http://localhost:5001"
echo ""
echo "   Authentication:"
echo "   POST /api/auth/login"
echo "   POST /api/auth/logout"
echo "   GET  /api/auth/me"
echo ""
echo "   Investigations:"
echo "   GET  /api/investigations"
echo "   POST /api/investigations"
echo "   GET  /api/investigations/{id}"
echo "   GET  /api/investigations/{id}/report"
echo ""
echo "   System Status:"
echo "   GET  /api/system/status"
echo "   GET  /api/mcp/servers"
echo ""
echo "   MCP Direct Access (if needed):"
echo "   Infrastructure: http://localhost:8021/execute"
echo "   Social Media:   http://localhost:8010/execute"
echo "   Threat Intel:   http://localhost:8020/execute"
echo "   Financial:      http://localhost:8040/execute"
echo "   Technical:      http://localhost:8050/execute"
echo ""
echo "📝 Example API Calls:"
echo "─────────────────────────"
echo ""
echo "1. Login:"
echo '   curl -X POST http://localhost:5001/api/auth/login \'
echo '   -H "Content-Type: application/json" \'
echo '   -d '\''{"username":"admin","password":"admin123"}'\'''
echo ""
echo "2. Create Investigation:"
echo '   curl -X POST http://localhost:5001/api/investigations \'
echo '   -H "Content-Type: application/json" \'
echo '   -H "Authorization: Bearer YOUR_TOKEN" \'
echo '   -d '\''{"target":"example.com","investigation_type":"comprehensive","priority":"high"}'\'''
echo ""
echo "3. Check System Status:"
echo '   curl http://localhost:5001/api/system/status'
echo ""
echo "🎉 All endpoints are ready for testing!"
echo "═══════════════════════════════════════════════════════════"