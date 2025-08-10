"""
Prometheus metrics configuration for FastAPI application
"""
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Request, Response
from fastapi.responses import PlainTextResponse
import time
import psutil
import structlog

logger = structlog.get_logger()

# HTTP metrics
http_requests_total = Counter(
    'http_requests_total',
    'Total number of HTTP requests',
    ['method', 'endpoint', 'status_code']
)

http_request_duration_seconds = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint']
)

http_requests_in_progress = Gauge(
    'http_requests_in_progress',
    'Number of HTTP requests currently being processed'
)

# Task metrics  
celery_tasks_total = Counter(
    'celery_tasks_total',
    'Total number of Celery tasks',
    ['task_name', 'status']
)

celery_task_duration_seconds = Histogram(
    'celery_task_duration_seconds',
    'Celery task duration in seconds',
    ['task_name']
)

celery_workers_active = Gauge(
    'celery_workers_active',
    'Number of active Celery workers'
)

# System metrics
system_cpu_usage = Gauge(
    'system_cpu_usage_percent',
    'System CPU usage percentage'
)

system_memory_usage = Gauge(
    'system_memory_usage_bytes',
    'System memory usage in bytes'
)

# OSINT specific metrics
osint_investigations_total = Counter(
    'osint_investigations_total',
    'Total number of OSINT investigations',
    ['investigation_type', 'status']
)

osint_api_calls_total = Counter(
    'osint_api_calls_total',
    'Total number of external API calls',
    ['api_provider', 'status']
)

osint_api_cost_total = Counter(
    'osint_api_cost_total',
    'Total cost of external API calls in USD',
    ['api_provider']
)


async def metrics_middleware(request: Request, call_next):
    """
    Middleware to collect HTTP metrics
    """
    start_time = time.time()
    
    # Increment in-progress counter
    http_requests_in_progress.inc()
    
    try:
        # Process request
        response = await call_next(request)
        
        # Calculate duration
        duration = time.time() - start_time
        
        # Extract metrics labels
        method = request.method
        endpoint = request.url.path
        status_code = response.status_code
        
        # Record metrics
        http_requests_total.labels(
            method=method,
            endpoint=endpoint,
            status_code=status_code
        ).inc()
        
        http_request_duration_seconds.labels(
            method=method,
            endpoint=endpoint
        ).observe(duration)
        
        return response
        
    except Exception as e:
        # Record error metrics
        duration = time.time() - start_time
        method = request.method
        endpoint = request.url.path
        
        http_requests_total.labels(
            method=method,
            endpoint=endpoint,
            status_code=500
        ).inc()
        
        http_request_duration_seconds.labels(
            method=method,
            endpoint=endpoint
        ).observe(duration)
        
        raise
        
    finally:
        # Decrement in-progress counter
        http_requests_in_progress.dec()


def update_system_metrics():
    """
    Update system resource metrics
    """
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=None)
        system_cpu_usage.set(cpu_percent)
        
        # Memory usage
        memory = psutil.virtual_memory()
        system_memory_usage.set(memory.used)
        
        logger.debug(
            "System metrics updated",
            cpu_percent=cpu_percent,
            memory_used_gb=round(memory.used / 1024**3, 2)
        )
        
    except Exception as e:
        logger.error("Failed to update system metrics", error=str(e))


def record_celery_task_metrics(task_name: str, status: str, duration: float = None):
    """
    Record Celery task execution metrics
    """
    try:
        celery_tasks_total.labels(
            task_name=task_name,
            status=status
        ).inc()
        
        if duration is not None:
            celery_task_duration_seconds.labels(
                task_name=task_name
            ).observe(duration)
            
    except Exception as e:
        logger.error("Failed to record Celery metrics", error=str(e))


def record_osint_metrics(investigation_type: str = None, api_provider: str = None, 
                        status: str = None, cost: float = None):
    """
    Record OSINT-specific metrics
    """
    try:
        if investigation_type and status:
            osint_investigations_total.labels(
                investigation_type=investigation_type,
                status=status
            ).inc()
            
        if api_provider:
            if status:
                osint_api_calls_total.labels(
                    api_provider=api_provider,
                    status=status
                ).inc()
                
            if cost:
                osint_api_cost_total.labels(
                    api_provider=api_provider
                ).inc(cost)
                
    except Exception as e:
        logger.error("Failed to record OSINT metrics", error=str(e))


async def metrics_endpoint(request):
    """
    Prometheus metrics endpoint
    """
    # Update system metrics before serving
    update_system_metrics()
    
    # Generate Prometheus format
    metrics_data = generate_latest()
    
    return PlainTextResponse(
        content=metrics_data.decode('utf-8'),
        media_type=CONTENT_TYPE_LATEST
    )


# Export all metrics for use in other modules
__all__ = [
    "metrics_middleware",
    "metrics_endpoint", 
    "record_celery_task_metrics",
    "record_osint_metrics",
    "update_system_metrics"
]