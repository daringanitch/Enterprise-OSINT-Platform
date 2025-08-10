"""
Celery configuration with Redis broker and result backend
"""
from celery import Celery, Task
from celery.signals import after_setup_logger
from functools import wraps
import structlog
import random
import time
from typing import Any, Callable

from app.core.config import settings

# Create Celery instance
celery_app = Celery(
    "osint_platform",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.tasks.osint_tasks",
        "app.tasks.report_tasks", 
        "app.tasks.mcp_tasks",
        "app.tasks.simple_tasks",
    ]
)

# Configure Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    result_expires=3600,
    timezone="UTC",
    enable_utc=True,
    
    # Task execution settings
    task_always_eager=settings.CELERY_TASK_ALWAYS_EAGER,
    task_eager_propagates=settings.CELERY_TASK_EAGER_PROPAGATES,
    task_time_limit=settings.CELERY_TASK_TIME_LIMIT,
    task_soft_time_limit=settings.CELERY_TASK_SOFT_TIME_LIMIT,
    
    # Worker settings
    worker_prefetch_multiplier=settings.CELERY_WORKER_PREFETCH_MULTIPLIER,
    worker_max_tasks_per_child=settings.CELERY_WORKER_MAX_TASKS_PER_CHILD,
    worker_disable_rate_limits=False,
    
    # Retry settings
    task_autoretry_for=(Exception,),
    task_max_retries=settings.TASK_MAX_RETRIES,
    task_default_retry_delay=settings.TASK_RETRY_DELAY,
    
    # Result backend settings
    result_backend_transport_options={
        'master_name': 'mymaster',
        'visibility_timeout': 3600,
        'fanout_prefix': True,
        'fanout_patterns': True
    },
    
    # Beat schedule for periodic tasks
    beat_schedule={
        'cleanup-old-reports': {
            'task': 'app.tasks.report_tasks.cleanup_old_reports',
            'schedule': 86400.0,  # Daily
        },
        'update-api-usage-metrics': {
            'task': 'app.tasks.osint_tasks.update_api_usage_metrics',
            'schedule': 300.0,  # Every 5 minutes
        },
    },
)

# Setup structured logging for Celery
logger = structlog.get_logger()


@after_setup_logger.connect
def setup_celery_logging(logger, *args, **kwargs):
    """Configure Celery to use structlog"""
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


class RetryTask(Task):
    """
    Custom task class with exponential backoff and jitter
    """
    autoretry_for = (Exception,)
    max_retries = settings.TASK_MAX_RETRIES
    default_retry_delay = settings.TASK_RETRY_DELAY
    retry_backoff = settings.TASK_RETRY_BACKOFF
    retry_jitter = settings.TASK_RETRY_JITTER
    
    def retry_with_backoff(self, exc=None, **kwargs):
        """
        Retry with exponential backoff and optional jitter
        """
        # Calculate backoff delay
        countdown = self.default_retry_delay * (self.retry_backoff ** self.request.retries)
        
        # Add jitter if enabled
        if self.retry_jitter:
            jitter = random.uniform(0, countdown * 0.1)  # 10% jitter
            countdown += jitter
        
        logger.warning(
            "Task retry scheduled",
            task_name=self.name,
            task_id=self.request.id,
            retry_count=self.request.retries + 1,
            countdown=round(countdown, 2),
            exception=str(exc) if exc else None
        )
        
        return self.retry(exc=exc, countdown=countdown, **kwargs)


def rate_limited_task(rate_limit: str = None):
    """
    Decorator for rate-limited tasks
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Apply rate limiting logic here
            # This is a simplified version - use Redis for distributed rate limiting
            return func(*args, **kwargs)
        
        # Set rate limit on the task
        if rate_limit:
            wrapper.rate_limit = rate_limit
        else:
            wrapper.rate_limit = settings.TASK_RATE_LIMIT
            
        return wrapper
    return decorator


# Task base class with monitoring
class MonitoredTask(RetryTask):
    """
    Task with built-in monitoring and metrics
    """
    def __call__(self, *args, **kwargs):
        start_time = time.time()
        task_id = self.request.id
        
        logger.info(
            "Task started",
            task_name=self.name,
            task_id=task_id,
            args=args,
            kwargs=kwargs
        )
        
        try:
            result = super().__call__(*args, **kwargs)
            
            duration = time.time() - start_time
            logger.info(
                "Task completed",
                task_name=self.name,
                task_id=task_id,
                duration=round(duration, 3)
            )
            
            # Record metrics
            try:
                from app.core.metrics import record_celery_task_metrics
                record_celery_task_metrics(self.name, "success", duration)
            except ImportError:
                pass  # Metrics not available in worker context
            
            return result
            
        except Exception as exc:
            duration = time.time() - start_time
            logger.error(
                "Task failed",
                task_name=self.name,
                task_id=task_id,
                duration=round(duration, 3),
                exception=str(exc),
                exc_info=True
            )
            
            # Record failure metrics
            try:
                from app.core.metrics import record_celery_task_metrics
                record_celery_task_metrics(self.name, "failure", duration)
            except ImportError:
                pass  # Metrics not available in worker context
            
            raise


# Set default task class
celery_app.Task = MonitoredTask


# Utility function for task chaining with error handling
def chain_tasks_with_fallback(tasks: list, fallback_task: Any = None):
    """
    Chain tasks with automatic fallback on failure
    """
    from celery import chain, chord, group
    
    if fallback_task:
        # Create a chord that runs fallback if any task fails
        return chord(
            group(*tasks),
            fallback_task.s()
        ).on_error(fallback_task.s())
    else:
        return chain(*tasks)


# Export celery app
__all__ = ["celery_app", "RetryTask", "MonitoredTask", "rate_limited_task"]