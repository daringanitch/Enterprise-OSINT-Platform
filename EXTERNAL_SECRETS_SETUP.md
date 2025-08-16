# External Secrets Operator Setup Guide

This guide walks through setting up External Secrets Operator (ESO) with HashiCorp Vault for secure secrets management in the OSINT Platform.

## Overview

External Secrets Operator provides secure integration between Kubernetes and external secret management systems. This setup enables:

- **Centralized Secret Management**: All secrets stored in Vault
- **Automatic Secret Rotation**: ESO automatically updates Kubernetes secrets when Vault secrets change
- **Audit Trail**: Complete audit trail of secret access via Vault
- **Compliance**: Enhanced security posture for GDPR/CCPA/PIPEDA compliance
- **Zero-Trust**: Secrets never stored in Kubernetes manifests or container images

## Prerequisites

- Kubernetes cluster with RBAC enabled
- Helm 3.x installed
- HashiCorp Vault deployed and accessible
- kubectl configured with cluster admin access

## Installation Steps

### 1. Install External Secrets Operator

```bash
# Add External Secrets Helm repository
helm repo add external-secrets https://charts.external-secrets.io
helm repo update

# Install External Secrets Operator
helm install external-secrets external-secrets/external-secrets \
  -n external-secrets-system \
  --create-namespace \
  --set installCRDs=true \
  --set prometheus.enabled=true
```

### 2. Verify Installation

```bash
# Check External Secrets Operator status
kubectl get pods -n external-secrets-system

# Verify CRDs are installed
kubectl get crd | grep external-secrets
```

Expected output:
```
clustersecretstores.external-secrets.io
externalsecrets.external-secrets.io
secretstores.external-secrets.io
```

### 3. Configure Vault Authentication

```bash
# Apply Vault configuration for ESO
kubectl apply -f k8s/vault-external-secrets-config.yaml

# Wait for Vault setup job to complete
kubectl wait --for=condition=complete job/vault-eso-setup -n osint-platform --timeout=300s

# Check job logs
kubectl logs job/vault-eso-setup -n osint-platform
```

### 4. Deploy External Secrets Configuration

```bash
# Apply External Secrets configuration
kubectl apply -f k8s/external-secrets-setup.yaml

# Verify SecretStore is ready
kubectl get secretstore vault-backend -n osint-platform
```

### 5. Verify External Secrets Creation

```bash
# Check that External Secrets are syncing
kubectl get externalsecrets -n osint-platform

# Verify Kubernetes secrets are created
kubectl get secrets -n osint-platform | grep "managed-by=external-secrets"
```

Expected secrets:
- `osint-api-keys`
- `osint-database-config`
- `osint-app-secrets`

### 6. Update Application Deployments

The backend deployment has been updated to use External Secrets. Deploy the updated configuration:

```bash
# Apply updated backend deployment
kubectl apply -f k8s/simple-backend-deployment.yaml

# Restart deployment to pick up new secrets
kubectl rollout restart deployment/osint-simple-backend -n osint-platform
```

## Vault Secret Structure

### API Keys (`secret/api-keys`)
```json
{
  "openai_api_key": "sk-...",
  "twitter_bearer_token": "AAAA...",
  "shodan_api_key": "ABC...",
  "virustotal_api_key": "def...",
  "github_token": "ghp_...",
  "linkedin_api_key": "78...",
  "reddit_api_key": "xyz..."
}
```

### Database Configuration (`secret/database-config`)
```json
{
  "postgres_user": "postgres",
  "postgres_password": "secure_password",
  "postgres_host": "postgresql",
  "postgres_port": "5432",
  "postgres_database": "osint_audit",
  "redis_host": "redis",
  "redis_port": "6379",
  "redis_db": "0"
}
```

### Application Configuration (`secret/app-config`)
```json
{
  "jwt_secret_key": "base64_encoded_key",
  "vault_token": "hvs.token",
  "encryption_key": "base64_encoded_key",
  "session_secret": "session_key",
  "webhook_secret": "webhook_key"
}
```

## Managing Secrets

### Adding New Secrets

1. **Add to Vault**:
```bash
vault kv put secret/api-keys new_service_key="value"
```

2. **Update ExternalSecret**:
```yaml
data:
- secretKey: new_service_key
  remoteRef:
    key: api-keys
    property: new_service_key
```

3. **Update target template**:
```yaml
template:
  data:
    new-service-key: "{{ .new_service_key }}"
```

### Rotating Secrets

1. **Update in Vault**:
```bash
vault kv put secret/api-keys openai_api_key="new_value"
```

2. **ESO automatically syncs** within the refresh interval (5 minutes for API keys)

3. **Restart applications** to pick up new secrets:
```bash
kubectl rollout restart deployment/osint-simple-backend -n osint-platform
```

## Monitoring and Troubleshooting

### Check External Secret Status

```bash
# Get detailed status
kubectl describe externalsecret osint-api-keys -n osint-platform

# Check events
kubectl get events -n osint-platform --field-selector involvedObject.kind=ExternalSecret
```

### Common Issues

#### 1. SecretStore Authentication Failed
```bash
# Check service account token
kubectl describe serviceaccount osint-vault-auth -n osint-platform

# Verify Vault role configuration
vault read auth/kubernetes/role/osint-platform-role
```

#### 2. Secret Not Syncing
```bash
# Check External Secrets Operator logs
kubectl logs -n external-secrets-system deployment/external-secrets -f

# Verify Vault connectivity
kubectl exec -it deployment/osint-simple-backend -n osint-platform -- vault status
```

#### 3. Permission Denied
```bash
# Check Vault policy
vault policy read osint-platform-policy

# Test policy with token
vault auth -method=kubernetes role=osint-platform-role
```

### Health Checks

```bash
# Run comprehensive health check
kubectl exec -it deployment/vault -n vault-system -- /config/health-check.sh

# Check ESO metrics
kubectl port-forward -n external-secrets-system service/external-secrets-metrics 8080:8080
curl http://localhost:8080/metrics
```

## Security Considerations

### 1. **Least Privilege Access**
- Each ExternalSecret uses specific Vault paths
- Service accounts have minimal required permissions
- Regular audit of Vault policies

### 2. **Secret Rotation**
- Automated rotation for application secrets
- API key rotation procedures documented
- Database credentials rotated quarterly

### 3. **Audit Trail**
- All secret access logged in Vault audit logs
- Kubernetes RBAC events captured
- Regular review of access patterns

### 4. **Backup and Recovery**
- Vault snapshots automated
- External Secrets configuration in Git
- Recovery procedures tested regularly

## Production Deployment Checklist

- [ ] Vault HA cluster deployed with TLS
- [ ] External Secrets Operator monitoring configured
- [ ] Secret rotation procedures documented
- [ ] Vault audit logging enabled
- [ ] Backup and recovery tested
- [ ] Security policies reviewed
- [ ] Compliance assessment completed
- [ ] Incident response procedures documented

## Compliance Benefits

### GDPR Compliance
- **Article 32**: Technical and organizational measures for security
- **Article 25**: Data protection by design and by default
- **Article 30**: Records of processing activities (audit logs)

### CCPA Compliance
- **Section 1798.81.5**: Reasonable security procedures
- **Section 1798.150**: Data security requirements

### PIPEDA Compliance
- **Principle 7**: Safeguards for personal information
- **Principle 8**: Openness about security measures

## Support and Maintenance

### Regular Tasks
- **Weekly**: Review External Secret sync status
- **Monthly**: Rotate application secrets
- **Quarterly**: Review and update Vault policies
- **Annually**: Complete security audit

### Emergency Procedures
- **Secret Compromise**: Immediate rotation and audit
- **Vault Outage**: Fallback to local secrets (documented)
- **ESO Failure**: Manual secret management procedures

For additional support, refer to:
- [External Secrets Operator Documentation](https://external-secrets.io/)
- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [Kubernetes Secrets Documentation](https://kubernetes.io/docs/concepts/configuration/secret/)