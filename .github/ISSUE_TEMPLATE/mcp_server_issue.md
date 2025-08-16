---
name: MCP Server Issue
about: Report issues with Model Context Protocol servers
title: '[MCP] '
labels: 'mcp, integration, needs-triage'
assignees: ''
---

## MCP Server Details
- **Server Type**: [Infrastructure/Social Media/Threat Intel/Technical/Financial]
- **Server Version**: [Enhanced/Basic]
- **Container Image**: [e.g., mcp-infrastructure-enhanced:latest]
- **Deployment**: [Kubernetes pod name or Docker container ID]

## Issue Description
A clear and concise description of the MCP server issue.

## Issue Category
- [ ] Server connectivity/health check failure
- [ ] Tool execution error
- [ ] Data format/parsing issue
- [ ] Performance/timeout issue
- [ ] Authentication/API key issue
- [ ] Rate limiting issue
- [ ] Capability discovery issue
- [ ] Protocol compliance issue

## External APIs Involved
Which external services is the MCP server attempting to access?
- [ ] WHOIS services
- [ ] DNS resolution
- [ ] Certificate transparency logs
- [ ] Twitter/X API
- [ ] LinkedIn API
- [ ] Reddit API
- [ ] VirusTotal API
- [ ] Shodan API
- [ ] HaveIBeenPwned API
- [ ] GitHub API
- [ ] Other: _______________

## Error Details

### Error Messages
```
Paste any error messages or stack traces here
```

### Tool Execution Details
- **Tool Name**: [e.g., whois_lookup, twitter_search, threat_check]
- **Parameters**: [Input parameters provided to the tool]
- **Expected Output**: [What you expected to receive]
- **Actual Output**: [What was actually returned]

### Health Check Status
```bash
# Output of health check endpoint
curl http://mcp-server:8000/health
```

## Investigation Context
- **Investigation ID**: [If applicable]
- **Target**: [Domain/IP/Username being investigated]
- **Investigation Type**: [Individual/Comprehensive/Custom]
- **Timestamp**: [When the error occurred]

## Network/Infrastructure
- [ ] Running in Kubernetes cluster
- [ ] Running with Docker Compose
- [ ] Local development setup
- [ ] Production environment
- [ ] Behind corporate firewall/proxy
- [ ] Using custom DNS servers

## Logs and Diagnostics

### MCP Server Logs
```
kubectl logs deployment/mcp-infrastructure-enhanced
# or
docker logs container-id
```

### Network Connectivity
```bash
# Test connectivity to external APIs
curl -I https://api.twitter.com
nslookup google.com
```

## API Configuration
- [ ] API keys are properly configured
- [ ] API keys have sufficient permissions
- [ ] Rate limits are within bounds
- [ ] API endpoints are accessible from deployment environment

## Troubleshooting Attempted
- [ ] Checked MCP server health endpoint
- [ ] Verified API key configuration
- [ ] Tested external API connectivity manually
- [ ] Reviewed server logs for errors
- [ ] Checked network policies/firewall rules
- [ ] Verified tool parameter formatting
- [ ] Tested with different input parameters
- [ ] Restarted MCP server container

## Expected vs Actual Behavior
**Expected**: What should happen when the MCP server tool is executed?

**Actual**: What is currently happening?

## Performance Impact
- [ ] Server response time > 30 seconds
- [ ] High memory usage (>500MB)
- [ ] High CPU usage (>80%)
- [ ] Tool execution failures
- [ ] Intermittent connectivity issues

## Additional Context
Include any other relevant details, configuration files, or environmental factors.