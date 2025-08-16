# Enterprise OSINT Platform - Deployment Guide

Complete guide for deploying the Enterprise OSINT Platform to Kubernetes in development, staging, and production environments.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Quick Start Deployment](#quick-start-deployment)
3. [Development Environment](#development-environment)
4. [Production Deployment](#production-deployment)
5. [High Availability Setup](#high-availability-setup)
6. [Security Hardening](#security-hardening)
7. [Monitoring and Maintenance](#monitoring-and-maintenance)
8. [Backup and Recovery](#backup-and-recovery)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Infrastructure Requirements

#### **Kubernetes Cluster**
- **Version**: Kubernetes 1.24+ (tested on 1.28+)
- **Nodes**: Minimum 3 nodes for production (1 node for development)
- **Memory**: 8GB RAM minimum per node (16GB recommended for production)
- **CPU**: 4 CPU cores minimum per node
- **Storage**: 100GB persistent storage (SSD recommended)

#### **Network Requirements**
- **Ingress Controller**: NGINX, Traefik, or similar
- **Load Balancer**: External load balancer for production
- **DNS**: Wildcard DNS for subdomains (optional)
- **Ports**: 80/443 for web access, additional ports for NodePort services

#### **Required Tools**
```bash
# Install required tools
kubectl --version  # v1.24+
helm --version     # v3.10+
docker --version  # v20.10+

# Optional but recommended
kubectx --version  # For context switching
stern --version    # For log streaming
k9s --version     # For cluster management
```

### External Dependencies

#### **Required Services**
- **PostgreSQL 15+**: Database for audit trail and investigations
- **Redis 7+**: Session management and caching
- **Persistent Storage**: StorageClass with ReadWriteOnce support

#### **Optional External APIs**
- **VirusTotal**: Threat intelligence (recommended)
- **Shodan**: Network intelligence (recommended)
- **OpenAI**: AI-powered analysis (optional)
- **AbuseIPDB**: IP reputation (optional)

---

## Quick Start Deployment

### Local Development with Docker Desktop

#### **1. Enable Kubernetes**
```bash
# Enable Kubernetes in Docker Desktop
# Settings → Kubernetes → Enable Kubernetes

# Verify cluster is running
kubectl cluster-info
```

#### **2. Deploy Platform**
```bash
# Clone repository
git clone <repository-url>
cd enterprise-osint-flask

# Create namespace
kubectl create namespace osint-platform

# Deploy core infrastructure
kubectl apply -f k8s/postgresql-deployment.yaml

# Wait for PostgreSQL to be ready
kubectl wait --for=condition=ready pod -l app=osint-platform-postgresql -n osint-platform --timeout=300s

# Deploy backend services
kubectl apply -f k8s/simple-backend-deployment.yaml

# Deploy frontend
kubectl apply -f k8s/simple-frontend-deployment.yaml

# Deploy MCP servers
kubectl apply -f k8s/enhanced-mcp-deployments.yaml
kubectl apply -f k8s/mcp-threat-enhanced-deployment.yaml
kubectl apply -f k8s/mcp-technical-enhanced-deployment.yaml
```

#### **3. Access the Platform**
```bash
# Port forward frontend
kubectl port-forward -n osint-platform svc/osint-simple-frontend 8080:80 &

# Port forward backend API
kubectl port-forward -n osint-platform svc/osint-backend 5000:5000 &

# Access the application
open http://localhost:8080
```

#### **4. Verify Deployment**
```bash
# Check all pods are running
kubectl get pods -n osint-platform

# Check service status via API
curl -s http://localhost:5000/api/system/status | jq
```

---

## Development Environment

### Complete Development Setup

#### **1. Infrastructure Setup**
```bash
# Create development namespace
kubectl create namespace osint-dev

# Deploy PostgreSQL with development settings
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgresql-dev
  namespace: osint-dev
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgresql-dev
  template:
    metadata:
      labels:
        app: postgresql-dev
    spec:
      containers:
      - name: postgresql
        image: postgres:15.5
        env:
        - name: POSTGRES_DB
          value: osint_audit
        - name: POSTGRES_USER
          value: postgres
        - name: POSTGRES_PASSWORD
          value: devpassword
        - name: POSTGRES_HOST_AUTH_METHOD
          value: trust
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
      volumes:
      - name: postgres-storage
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: postgresql-dev
  namespace: osint-dev
spec:
  selector:
    app: postgresql-dev
  ports:
  - port: 5432
    targetPort: 5432
EOF
```

#### **2. Development Configuration**
```bash
# Create development secrets
kubectl create secret generic osint-dev-secrets \
  --namespace=osint-dev \
  --from-literal=jwt-secret-key=dev-secret-key \
  --from-literal=postgres-password=devpassword

# Optional: Add API keys for testing
kubectl create secret generic osint-api-keys \
  --namespace=osint-dev \
  --from-literal=virustotal-api-key="${VIRUSTOTAL_API_KEY}" \
  --from-literal=openai-api-key="${OPENAI_API_KEY}"
```

#### **3. Deploy Development Stack**
```bash
# Deploy with development configurations
sed 's/osint-platform/osint-dev/g' k8s/simple-backend-deployment.yaml | \
  sed 's/latest/dev/g' | \
  kubectl apply -f -

sed 's/osint-platform/osint-dev/g' k8s/simple-frontend-deployment.yaml | \
  sed 's/latest/dev/g' | \
  kubectl apply -f -

# Deploy MCP servers for development
sed 's/osint-platform/osint-dev/g' k8s/enhanced-mcp-deployments.yaml | \
  kubectl apply -f -
```

---

## Production Deployment

### Production-Ready Configuration

#### **1. Pre-Production Checklist**

**Security Requirements:**
- [ ] Strong JWT secret key (256-bit minimum)
- [ ] Secure database passwords
- [ ] TLS certificates obtained
- [ ] API keys secured in external secret management
- [ ] Network policies configured
- [ ] RBAC policies defined

**Infrastructure Requirements:**
- [ ] Multi-node Kubernetes cluster
- [ ] Persistent storage provisioned
- [ ] Load balancer configured
- [ ] Backup strategy implemented
- [ ] Monitoring solution deployed

#### **2. Production Secrets Setup**

```bash
# Generate secure JWT secret
JWT_SECRET=$(openssl rand -base64 32)

# Create production secrets
kubectl create secret generic osint-production-secrets \
  --namespace=osint-platform \
  --from-literal=jwt-secret-key="${JWT_SECRET}" \
  --from-literal=postgres-password="${SECURE_DB_PASSWORD}"

# Store API keys securely
kubectl create secret generic osint-api-keys \
  --namespace=osint-platform \
  --from-literal=virustotal-api-key="${VIRUSTOTAL_API_KEY}" \
  --from-literal=abuseipdb-api-key="${ABUSEIPDB_API_KEY}" \
  --from-literal=shodan-api-key="${SHODAN_API_KEY}" \
  --from-literal=openai-api-key="${OPENAI_API_KEY}"
```

#### **3. Production Database Setup**

```bash
# Create PostgreSQL with production configuration
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgresql-production
  namespace: osint-platform
spec:
  serviceName: postgresql-production
  replicas: 1
  selector:
    matchLabels:
      app: postgresql-production
  template:
    metadata:
      labels:
        app: postgresql-production
    spec:
      containers:
      - name: postgresql
        image: postgres:15.5
        env:
        - name: POSTGRES_DB
          value: osint_audit
        - name: POSTGRES_USER
          value: postgres
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: osint-production-secrets
              key: postgres-password
        - name: POSTGRES_SHARED_BUFFERS
          value: "256MB"
        - name: POSTGRES_EFFECTIVE_CACHE_SIZE
          value: "1GB"
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-data
          mountPath: /var/lib/postgresql/data
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - postgres
          initialDelaySeconds: 30
          timeoutSeconds: 5
        readinessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - postgres
          initialDelaySeconds: 5
          timeoutSeconds: 1
  volumeClaimTemplates:
  - metadata:
      name: postgres-data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 100Gi
      storageClassName: fast-ssd  # Use your storage class
---
apiVersion: v1
kind: Service
metadata:
  name: postgresql-production
  namespace: osint-platform
spec:
  selector:
    app: postgresql-production
  ports:
  - port: 5432
    targetPort: 5432
  clusterIP: None
EOF
```

#### **4. Production Backend Deployment**

```bash
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: osint-backend-production
  namespace: osint-platform
  labels:
    app: osint-backend
    environment: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: osint-backend
  template:
    metadata:
      labels:
        app: osint-backend
        environment: production
    spec:
      containers:
      - name: backend
        image: osint-platform/simple-backend:latest
        imagePullPolicy: Always
        ports:
        - containerPort: 5000
        env:
        - name: FLASK_ENV
          value: "production"
        - name: LOG_LEVEL
          value: "INFO"
        - name: POSTGRES_URL
          value: "postgresql://postgres:$(POSTGRES_PASSWORD)@postgresql-production:5432/osint_audit"
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: osint-production-secrets
              key: postgres-password
        - name: JWT_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: osint-production-secrets
              key: jwt-secret-key
        - name: MCP_INFRASTRUCTURE_URL
          value: "http://mcp-infrastructure-enhanced:8021"
        - name: MCP_THREAT_URL
          value: "http://mcp-threat-enhanced:8020"
        - name: MCP_AI_URL
          value: "http://mcp-technical-enhanced:8050"
        resources:
          requests:
            memory: "512Mi"
            cpu: "200m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /api/system/status
            port: 5000
          initialDelaySeconds: 30
          periodSeconds: 30
          timeoutSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/system/status
            port: 5000
          initialDelaySeconds: 5
          periodSeconds: 10
          timeoutSeconds: 5
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
---
apiVersion: v1
kind: Service
metadata:
  name: osint-backend
  namespace: osint-platform
  labels:
    app: osint-backend
spec:
  selector:
    app: osint-backend
  ports:
  - port: 5000
    targetPort: 5000
    protocol: TCP
  type: ClusterIP
EOF
```

#### **5. Production MCP Servers**

```bash
# Deploy production MCP servers with proper resource limits
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-infrastructure-enhanced
  namespace: osint-platform
spec:
  replicas: 2
  selector:
    matchLabels:
      app: mcp-infrastructure-enhanced
  template:
    metadata:
      labels:
        app: mcp-infrastructure-enhanced
    spec:
      containers:
      - name: infrastructure-enhanced
        image: osint-platform/infrastructure-advanced:latest
        imagePullPolicy: Never
        ports:
        - containerPort: 8021
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8021
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8021
          initialDelaySeconds: 5
          periodSeconds: 10
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
---
apiVersion: v1
kind: Service
metadata:
  name: mcp-infrastructure-enhanced
  namespace: osint-platform
spec:
  selector:
    app: mcp-infrastructure-enhanced
  ports:
  - port: 8021
    targetPort: 8021
EOF
```

---

## High Availability Setup

### Multi-Region Deployment

#### **1. Database High Availability**

```bash
# PostgreSQL with primary-replica setup
cat <<EOF | kubectl apply -f -
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: postgresql-ha
  namespace: osint-platform
spec:
  instances: 3
  primaryUpdateStrategy: unsupervised
  
  postgresql:
    parameters:
      max_connections: "200"
      shared_buffers: "256MB"
      effective_cache_size: "1GB"
      
  bootstrap:
    initdb:
      database: osint_audit
      owner: postgres
      secret:
        name: osint-production-secrets
        
  storage:
    size: 100Gi
    storageClass: fast-ssd
    
  monitoring:
    enabled: true
EOF
```

#### **2. Load Balancing Configuration**

```bash
# Application load balancer
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: osint-backend-lb
  namespace: osint-platform
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
spec:
  type: LoadBalancer
  selector:
    app: osint-backend
  ports:
  - port: 80
    targetPort: 5000
    protocol: TCP
---
apiVersion: v1
kind: Service
metadata:
  name: osint-frontend-lb
  namespace: osint-platform
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
spec:
  type: LoadBalancer
  selector:
    app: osint-simple-frontend
  ports:
  - port: 80
    targetPort: 80
    protocol: TCP
EOF
```

#### **3. Horizontal Pod Autoscaling**

```bash
# Backend autoscaling
cat <<EOF | kubectl apply -f -
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: osint-backend-hpa
  namespace: osint-platform
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: osint-backend-production
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: mcp-infrastructure-hpa
  namespace: osint-platform
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: mcp-infrastructure-enhanced
  minReplicas: 2
  maxReplicas: 5
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 80
EOF
```

---

## Security Hardening

### Network Security

#### **1. Network Policies**

```bash
# Network policy for backend
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-network-policy
  namespace: osint-platform
spec:
  podSelector:
    matchLabels:
      app: osint-backend
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: osint-simple-frontend
    - podSelector: {}  # Allow from same namespace
    ports:
    - protocol: TCP
      port: 5000
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgresql-production
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - podSelector:
        matchLabels:
          app: mcp-infrastructure-enhanced
    ports:
    - protocol: TCP
      port: 8021
  - to: []  # Allow external API calls
    ports:
    - protocol: TCP
      port: 443
    - protocol: TCP
      port: 80
EOF
```

#### **2. Pod Security Standards**

```bash
# Pod security policy
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: osint-platform
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
EOF
```

#### **3. RBAC Configuration**

```bash
# Service account for backend
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: osint-backend-sa
  namespace: osint-platform
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: osint-backend-role
  namespace: osint-platform
rules:
- apiGroups: [""]
  resources: ["pods", "services", "endpoints"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
  resourceNames: ["osint-production-secrets", "osint-api-keys"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: osint-backend-rolebinding
  namespace: osint-platform
subjects:
- kind: ServiceAccount
  name: osint-backend-sa
  namespace: osint-platform
roleRef:
  kind: Role
  name: osint-backend-role
  apiGroup: rbac.authorization.k8s.io
EOF
```

### TLS/SSL Configuration

#### **1. Certificate Management**

```bash
# Install cert-manager for automatic certificates
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Create ClusterIssuer for Let's Encrypt
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@yourdomain.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
EOF
```

#### **2. Ingress with TLS**

```bash
# Ingress configuration with TLS
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: osint-platform-ingress
  namespace: osint-platform
  annotations:
    kubernetes.io/ingress.class: "nginx"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - osint.yourdomain.com
    - api.osint.yourdomain.com
    secretName: osint-platform-tls
  rules:
  - host: osint.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: osint-simple-frontend
            port:
              number: 80
  - host: api.osint.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: osint-backend
            port:
              number: 5000
EOF
```

---

## Monitoring and Maintenance

### Prometheus Monitoring Setup

#### **1. Deploy Prometheus Stack**

```bash
# Add Prometheus Helm repository
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Install Prometheus, Grafana, and AlertManager
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.resources.requests.storage=50Gi \
  --set grafana.persistence.enabled=true \
  --set grafana.persistence.size=10Gi
```

#### **2. Custom ServiceMonitor**

```bash
# ServiceMonitor for OSINT platform
cat <<EOF | kubectl apply -f -
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: osint-platform-monitor
  namespace: osint-platform
  labels:
    app: osint-platform
spec:
  selector:
    matchLabels:
      app: osint-backend
  endpoints:
  - port: metrics
    path: /metrics
    interval: 30s
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: osint-mcp-monitor
  namespace: osint-platform
spec:
  selector:
    matchExpressions:
    - key: app
      operator: In
      values:
      - mcp-infrastructure-enhanced
      - mcp-threat-enhanced
      - mcp-technical-enhanced
  endpoints:
  - port: metrics
    path: /metrics
    interval: 30s
EOF
```

### Log Aggregation

#### **1. Deploy ELK Stack**

```bash
# Add Elastic Helm repository
helm repo add elastic https://helm.elastic.co
helm repo update

# Install Elasticsearch
helm install elasticsearch elastic/elasticsearch \
  --namespace logging \
  --create-namespace \
  --set replicas=3 \
  --set volumeClaimTemplate.resources.requests.storage=50Gi

# Install Kibana
helm install kibana elastic/kibana \
  --namespace logging \
  --set service.type=LoadBalancer

# Install Filebeat for log collection
helm install filebeat elastic/filebeat \
  --namespace logging \
  --set daemonset.enabled=true
```

#### **2. Custom Logging Configuration**

```bash
# Filebeat configuration for OSINT platform
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: filebeat-config
  namespace: logging
data:
  filebeat.yml: |
    filebeat.autodiscover:
      providers:
        - type: kubernetes
          node: \${NODE_NAME}
          hints.enabled: true
          hints.default_config:
            type: container
            paths:
              - /var/log/containers/*\${data.kubernetes.container.id}.log
    
    processors:
      - add_kubernetes_metadata:
          host: \${NODE_NAME}
          matchers:
          - logs_path:
              logs_path: "/var/log/containers/"
      - decode_json_fields:
          fields: ["message"]
          target: ""
          overwrite_keys: true
    
    output.elasticsearch:
      hosts: ["elasticsearch-master:9200"]
      index: "osint-platform-%{+yyyy.MM.dd}"
EOF
```

---

## Backup and Recovery

### Database Backup Strategy

#### **1. Automated Backups**

```bash
# PostgreSQL backup CronJob
cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgresql-backup
  namespace: osint-platform
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: postgres:15.5
            env:
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef:
                  name: osint-production-secrets
                  key: postgres-password
            command:
            - /bin/bash
            - -c
            - |
              DATE=\$(date +%Y%m%d_%H%M%S)
              pg_dump -h postgresql-production -U postgres osint_audit > /backup/osint_audit_\${DATE}.sql
              # Upload to S3 or other storage
              # aws s3 cp /backup/osint_audit_\${DATE}.sql s3://your-backup-bucket/
            volumeMounts:
            - name: backup-storage
              mountPath: /backup
          volumes:
          - name: backup-storage
            persistentVolumeClaim:
              claimName: backup-pvc
          restartPolicy: OnFailure
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: backup-pvc
  namespace: osint-platform
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 50Gi
EOF
```

#### **2. Disaster Recovery Procedure**

```bash
# Database restoration script
cat <<'EOF' > restore-database.sh
#!/bin/bash
set -e

BACKUP_FILE=$1
if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

echo "Restoring database from $BACKUP_FILE"

# Scale down backend to prevent connections
kubectl scale deployment osint-backend-production --replicas=0 -n osint-platform

# Wait for backend to scale down
kubectl wait --for=delete pod -l app=osint-backend -n osint-platform --timeout=60s

# Restore database
kubectl exec -i postgresql-production-0 -n osint-platform -- \
    psql -U postgres -c "DROP DATABASE IF EXISTS osint_audit;"

kubectl exec -i postgresql-production-0 -n osint-platform -- \
    psql -U postgres -c "CREATE DATABASE osint_audit;"

kubectl exec -i postgresql-production-0 -n osint-platform -- \
    psql -U postgres osint_audit < "$BACKUP_FILE"

# Scale backend back up
kubectl scale deployment osint-backend-production --replicas=3 -n osint-platform

echo "Database restoration completed"
EOF

chmod +x restore-database.sh
```

### Configuration Backup

```bash
# Backup Kubernetes configurations
mkdir -p backups/$(date +%Y%m%d)
kubectl get all,secrets,configmaps,pvc -n osint-platform -o yaml > backups/$(date +%Y%m%d)/osint-platform-backup.yaml

# Backup Helm values
helm get values prometheus -n monitoring > backups/$(date +%Y%m%d)/prometheus-values.yaml
```

---

## Troubleshooting

### Common Issues and Solutions

#### **1. Pods Stuck in Pending State**

```bash
# Check node resources
kubectl describe nodes

# Check pod events
kubectl describe pod <pod-name> -n osint-platform

# Check storage availability
kubectl get pv,pvc -n osint-platform

# Common fixes:
# - Increase node resources
# - Check storage class availability
# - Verify resource requests vs limits
```

#### **2. Database Connection Issues**

```bash
# Test database connectivity
kubectl exec -it deployment/osint-backend -n osint-platform -- \
    python -c "
import psycopg2
import os
try:
    conn = psycopg2.connect(os.environ['POSTGRES_URL'])
    print('Database connection successful')
except Exception as e:
    print(f'Database connection failed: {e}')
"

# Check database pod logs
kubectl logs postgresql-production-0 -n osint-platform

# Verify secrets
kubectl get secret osint-production-secrets -n osint-platform -o yaml
```

#### **3. MCP Server Communication Failures**

```bash
# Test MCP server connectivity
kubectl exec -it deployment/osint-backend -n osint-platform -- \
    curl -s http://mcp-infrastructure-enhanced:8021/health

# Check MCP server logs
kubectl logs deployment/mcp-infrastructure-enhanced -n osint-platform

# Verify service discovery
kubectl exec -it deployment/osint-backend -n osint-platform -- \
    nslookup mcp-infrastructure-enhanced
```

#### **4. Performance Issues**

```bash
# Check resource usage
kubectl top nodes
kubectl top pods -n osint-platform

# Check database performance
kubectl exec -it postgresql-production-0 -n osint-platform -- \
    psql -U postgres -c "
    SELECT query, mean_exec_time, calls 
    FROM pg_stat_statements 
    ORDER BY mean_exec_time DESC 
    LIMIT 10;"

# Check application metrics
kubectl port-forward -n osint-platform svc/osint-backend 5000:5000 &
curl -s http://localhost:5000/api/system/status
```

### Debug Commands Reference

```bash
# Get all resources in namespace
kubectl get all -n osint-platform

# Stream logs from all pods
stern -n osint-platform .

# Check cluster events
kubectl get events -n osint-platform --sort-by='.lastTimestamp'

# Port forward for debugging
kubectl port-forward -n osint-platform svc/osint-backend 5000:5000
kubectl port-forward -n osint-platform svc/osint-simple-frontend 8080:80

# Execute commands in pods
kubectl exec -it deployment/osint-backend -n osint-platform -- /bin/bash

# Check resource quotas
kubectl describe resourcequota -n osint-platform

# Check network policies
kubectl get networkpolicy -n osint-platform
```

### Performance Tuning

#### **Database Optimization**

```bash
# Optimize PostgreSQL configuration
kubectl exec -it postgresql-production-0 -n osint-platform -- \
    psql -U postgres -c "
    ALTER SYSTEM SET shared_buffers = '512MB';
    ALTER SYSTEM SET effective_cache_size = '2GB';
    ALTER SYSTEM SET maintenance_work_mem = '128MB';
    ALTER SYSTEM SET checkpoint_completion_target = 0.9;
    SELECT pg_reload_conf();
    "
```

#### **Application Tuning**

```bash
# Adjust resource limits based on monitoring
kubectl patch deployment osint-backend-production -n osint-platform -p '
{
  "spec": {
    "template": {
      "spec": {
        "containers": [
          {
            "name": "backend",
            "resources": {
              "requests": {
                "memory": "1Gi",
                "cpu": "500m"
              },
              "limits": {
                "memory": "2Gi",
                "cpu": "2000m"
              }
            }
          }
        ]
      }
    }
  }
}'
```

For additional support and advanced configurations, refer to the [Configuration Reference](CONFIGURATION.md) and [Architecture Overview](ARCHITECTURE_OVERVIEW.md).