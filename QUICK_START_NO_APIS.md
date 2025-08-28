# Quick Start Guide - Running Without API Keys

This guide helps you run the Enterprise OSINT Platform without external API keys, perfect for testing and evaluation.

## What You Can Do Without API Keys

### ✅ Full Platform Features Available:
- **User Management**: Login with admin/admin123
- **Investigation Creation**: Start new investigations
- **Report Generation**: Create professional PDF reports
- **Monitoring**: View Prometheus metrics and Grafana dashboards
- **Audit Logging**: Full compliance tracking

### ✅ Intelligence Sources (No API Needed):
- **DNS Lookups**: Using public DNS servers
- **WHOIS Queries**: Public WHOIS databases
- **SSL Certificate Analysis**: Direct certificate inspection
- **Basic Web Scraping**: Public website analysis
- **Technology Detection**: Based on HTTP headers and responses

### ⚠️ Limited Features (Mock Data):
- **Social Media Intelligence**: Returns example data
- **Threat Intelligence**: Simulated threat scores
- **AI Analysis**: Basic pattern matching instead of GPT-4
- **Financial Intelligence**: Sample SEC filing data

## Quick Deployment Steps

### 1. Ensure Configuration is Set
```bash
# Your .env file already has the minimum required:
cat .env
```

### 2. Deploy to Local Kubernetes
```bash
# Create namespace
kubectl create namespace osint-platform

# Deploy core services
kubectl apply -f k8s/postgresql-deployment.yaml
kubectl apply -f k8s/simple-backend-deployment.yaml
kubectl apply -f k8s/simple-frontend-deployment.yaml

# Optional: Deploy monitoring
kubectl apply -f k8s/monitoring-stack.yaml
kubectl apply -f k8s/health-monitoring.yaml
```

### 3. Deploy MCP Servers (They work without APIs)
```bash
# These provide basic functionality without external APIs
kubectl apply -f k8s/mcp-infrastructure-deployment.yaml
kubectl apply -f k8s/mcp-threat-enhanced-deployment.yaml
kubectl apply -f k8s/mcp-social-deployment.yaml
```

### 4. Access the Platform
```bash
# Port forward the frontend
kubectl port-forward -n osint-platform svc/osint-simple-frontend 8080:80

# Port forward the backend (if needed for direct API access)
kubectl port-forward -n osint-platform svc/osint-backend 5000:5000
```

### 5. Login and Test
1. Open http://localhost:8080
2. Login with:
   - Username: `admin`
   - Password: `admin123`
3. Create a test investigation with domain: `example.com`

## Testing Without APIs

### Example Investigation Targets:
- `google.com` - Test DNS and WHOIS lookups
- `github.com` - Test SSL certificate analysis
- `example.com` - Safe testing domain
- Your own domain - Test real infrastructure data

### What to Expect:
- **Infrastructure results**: Real DNS, WHOIS, SSL data
- **Social/Threat results**: Mock data with warnings
- **Reports**: Professional PDFs with available data
- **Monitoring**: Real metrics about platform performance

## Getting Free API Keys (When Ready)

### Free Tier Available:
1. **OpenAI**: Free credits for new accounts
   - Sign up at: https://platform.openai.com
   - Free tier: ~$5 in credits

2. **VirusTotal**: Free community API
   - Sign up at: https://www.virustotal.com/gui/join-us
   - Free tier: 500 requests/day

3. **Shodan**: Academic/Researcher access
   - Sign up at: https://account.shodan.io/register
   - Free tier: Limited queries

4. **AbuseIPDB**: Free tier available
   - Sign up at: https://www.abuseipdb.com/register
   - Free tier: 1000 checks/day

5. **GitHub**: Personal access token
   - Create at: https://github.com/settings/tokens
   - Free tier: 5000 requests/hour

### Adding API Keys Later:
Simply update your `.env` file:
```bash
# Edit .env and add:
OPENAI_API_KEY=your-key-here
VIRUSTOTAL_API_KEY=your-key-here
# etc...

# Restart the backend pod to pick up new keys
kubectl rollout restart deployment/osint-backend -n osint-platform
```

## Demo Mode Benefits

Running without API keys is perfect for:
- 🧪 Testing the platform architecture
- 📊 Evaluating the user interface
- 🔍 Understanding the investigation workflow
- 📈 Setting up monitoring and metrics
- 🔒 Testing security and compliance features

The platform will clearly indicate when mock data is being used, so you'll know exactly what's real vs. simulated.

## Next Steps

1. **Deploy and explore** the platform with mock data
2. **Test core workflows** with public data sources
3. **Set up monitoring** to understand system behavior
4. **Plan which APIs** you actually need based on use cases
5. **Add API keys incrementally** as needed

Remember: The platform is fully functional without external APIs - you just get limited enrichment data!