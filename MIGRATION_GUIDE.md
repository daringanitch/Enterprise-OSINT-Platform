# Flask to FastAPI Migration Guide

## Overview

This guide covers the migration from Flask (WSGI) to FastAPI (ASGI) for the Enterprise OSINT Platform, providing better async I/O support for high-fanout OSINT calls.

## Key Improvements

### 1. **Async/Await Support**
- Native async support for concurrent API calls
- Better handling of I/O-bound operations
- Improved performance for parallel OSINT data collection

### 2. **Celery with Retry Logic**
- Exponential backoff with jitter
- Circuit breaker pattern for external APIs
- Task monitoring and backpressure handling
- Distributed rate limiting

### 3. **Production-Ready Deployment**
- Gunicorn with Uvicorn workers
- Horizontal pod autoscaling
- Prometheus metrics integration
- Health checks and readiness probes

## Migration Steps

### 1. Build New Docker Images

```bash
# Build FastAPI backend image
docker build -t osint-platform/fastapi-backend:latest -f fastapi-backend/Dockerfile fastapi-backend/

# Build Celery worker image (uses same image)
docker tag osint-platform/fastapi-backend:latest osint-platform/celery-worker:latest
```

### 2. Deploy to Kubernetes

```bash
# Apply new deployments
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/redis-deployment.yaml
kubectl apply -f k8s/postgresql-deployment.yaml
kubectl apply -f k8s/reports-pvc.yaml
kubectl apply -f k8s/fastapi-backend-deployment.yaml
kubectl apply -f k8s/celery-workers-deployment.yaml
```

### 3. Database Migration

The FastAPI backend uses the same database schema, but with async SQLAlchemy:

```bash
# Run database migrations
kubectl exec -it deployment/osint-fastapi-backend -n osint-platform -- alembic upgrade head
```

### 4. Monitor Deployment

```bash
# Check pod status
kubectl get pods -n osint-platform

# View logs
kubectl logs -f deployment/osint-fastapi-backend -n osint-platform
kubectl logs -f deployment/osint-celery-worker -n osint-platform

# Access Flower UI for Celery monitoring
kubectl port-forward -n osint-platform svc/osint-celery-flower 5555:5555
# Visit http://localhost:5555 (admin/admin)
```

## API Changes

### Authentication
- Same JWT-based authentication
- New endpoint: `POST /api/v1/auth/refresh` for token refresh

### Investigation Endpoints
- `POST /api/v1/investigations` - Create investigation (async)
- `POST /api/v1/investigations/bulk` - Bulk create
- `GET /api/v1/investigations/{id}/summary` - Get summary
- `POST /api/v1/investigations/{id}/export` - Export data

### New Features
- WebSocket support for real-time updates
- Server-sent events for investigation progress
- Batch operations with better concurrency

## Configuration

### Environment Variables

```bash
# FastAPI specific
WORKERS=4
HOST=0.0.0.0
PORT=8000

# Celery configuration
CELERY_WORKER_PREFETCH_MULTIPLIER=4
CELERY_WORKER_MAX_TASKS_PER_CHILD=1000
TASK_MAX_RETRIES=3
TASK_RETRY_DELAY=60
TASK_RETRY_BACKOFF=2.0
TASK_RETRY_JITTER=true

# Rate limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_DEFAULT=100/minute
MAX_CONCURRENT_INVESTIGATIONS=10

# Monitoring
PROMETHEUS_ENABLED=true
SENTRY_DSN=your-sentry-dsn
```

## Performance Tuning

### 1. **Connection Pooling**
```python
# Async PostgreSQL with connection pool
engine = create_async_engine(
    DATABASE_URL,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True
)
```

### 2. **Redis Optimization**
```python
# Use Redis connection pool
redis = await redis.from_url(
    REDIS_URL,
    encoding="utf-8",
    decode_responses=True,
    max_connections=50
)
```

### 3. **Task Queue Optimization**
- Separate queues for different task types
- Priority queues for critical tasks
- Dead letter queue for failed tasks

## Monitoring

### Prometheus Metrics
- `osint_tasks_total` - Total tasks by status
- `osint_task_duration_seconds` - Task execution time
- `osint_active_tasks` - Currently running tasks
- `osint_api_calls_total` - External API calls
- `osint_rate_limit_hits_total` - Rate limit violations

### Health Checks
- `/health` - Basic health check
- `/health/ready` - Readiness probe (checks dependencies)
- `/metrics` - Prometheus metrics endpoint

## Rollback Plan

If issues arise:

1. Scale down new deployments:
```bash
kubectl scale deployment osint-fastapi-backend --replicas=0 -n osint-platform
kubectl scale deployment osint-celery-worker --replicas=0 -n osint-platform
```

2. Scale up old Flask deployments:
```bash
kubectl scale deployment osint-backend --replicas=3 -n osint-platform
```

3. Monitor and investigate issues before retry

## Testing

### Load Testing
```bash
# Use locust for load testing
pip install locust
locust -f tests/load_test.py --host=http://localhost:8000
```

### Integration Testing
```bash
# Run integration tests
pytest tests/integration/ -v
```

## Support

For issues or questions:
- Check logs: `kubectl logs -f deployment/osint-fastapi-backend -n osint-platform`
- Monitor Celery: Access Flower UI
- Review metrics: Check Prometheus/Grafana dashboards