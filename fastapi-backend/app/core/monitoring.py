"""
Task monitoring and backpressure handling
"""
from typing import Dict, List, Optional, Any
import asyncio
from datetime import datetime, timedelta
import redis.asyncio as redis
from prometheus_client import Counter, Gauge, Histogram, CollectorRegistry
import structlog

from app.core.config import settings
from app.core.celery_app import celery_app

logger = structlog.get_logger()

# Prometheus metrics
registry = CollectorRegistry()

# Task metrics
task_counter = Counter(
    'osint_tasks_total',
    'Total number of tasks processed',
    ['task_name', 'status'],
    registry=registry
)

task_duration = Histogram(
    'osint_task_duration_seconds',
    'Task duration in seconds',
    ['task_name'],
    registry=registry
)

active_tasks = Gauge(
    'osint_active_tasks',
    'Number of currently active tasks',
    ['task_name'],
    registry=registry
)

queue_size = Gauge(
    'osint_queue_size',
    'Number of tasks in queue',
    ['queue_name'],
    registry=registry
)

# API rate limit metrics
api_calls = Counter(
    'osint_api_calls_total',
    'Total API calls made',
    ['api_name', 'status'],
    registry=registry
)

api_rate_limit_hits = Counter(
    'osint_rate_limit_hits_total',
    'Number of rate limit hits',
    ['api_name'],
    registry=registry
)


class TaskMonitor:
    """
    Monitor Celery tasks and implement backpressure
    """
    
    def __init__(self, redis_url: str = None):
        self.redis_url = redis_url or settings.REDIS_URL
        self._redis: Optional[redis.Redis] = None
        self._monitor_task: Optional[asyncio.Task] = None
    
    async def start(self):
        """Start monitoring tasks"""
        self._redis = await redis.from_url(self.redis_url)
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info("Task monitor started")
    
    async def stop(self):
        """Stop monitoring tasks"""
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        if self._redis:
            await self._redis.close()
        
        logger.info("Task monitor stopped")
    
    async def _monitor_loop(self):
        """Main monitoring loop"""
        while True:
            try:
                await self._update_metrics()
                await asyncio.sleep(10)  # Update every 10 seconds
            except Exception as e:
                logger.error("Error in monitor loop", error=str(e))
                await asyncio.sleep(30)  # Back off on error
    
    async def _update_metrics(self):
        """Update Prometheus metrics"""
        # Get Celery stats
        stats = await self._get_celery_stats()
        
        # Update queue size metrics
        for queue_name, size in stats.get('queues', {}).items():
            queue_size.labels(queue_name=queue_name).set(size)
        
        # Update active tasks
        for task_name, count in stats.get('active_tasks', {}).items():
            active_tasks.labels(task_name=task_name).set(count)
    
    async def _get_celery_stats(self) -> Dict[str, Any]:
        """Get Celery statistics"""
        try:
            # Get queue lengths
            queues = {}
            for queue in ['celery', 'osint', 'reports']:
                length = await self._redis.llen(f"celery:queue:{queue}")
                queues[queue] = length
            
            # Get active tasks from Celery inspect
            inspect = celery_app.control.inspect()
            active = inspect.active()
            
            active_tasks = {}
            if active:
                for worker, tasks in active.items():
                    for task in tasks:
                        task_name = task.get('name', 'unknown')
                        active_tasks[task_name] = active_tasks.get(task_name, 0) + 1
            
            return {
                'queues': queues,
                'active_tasks': active_tasks,
                'timestamp': datetime.utcnow()
            }
        except Exception as e:
            logger.error("Failed to get Celery stats", error=str(e))
            return {}
    
    async def check_backpressure(self, task_name: str) -> bool:
        """
        Check if we should apply backpressure for a task
        Returns True if task should be delayed
        """
        try:
            # Check queue size
            queue_length = await self._redis.llen(f"celery:queue:osint")
            if queue_length > settings.MAX_QUEUE_SIZE:
                logger.warning(
                    "Backpressure: Queue too long",
                    task_name=task_name,
                    queue_length=queue_length
                )
                return True
            
            # Check active task count
            active_count = await self._redis.get(f"active_tasks:{task_name}")
            if active_count and int(active_count) > settings.MAX_CONCURRENT_TASKS:
                logger.warning(
                    "Backpressure: Too many active tasks",
                    task_name=task_name,
                    active_count=int(active_count)
                )
                return True
            
            # Check rate limits
            rate_limit_key = f"rate_limit:{task_name}"
            current_count = await self._redis.incr(rate_limit_key)
            
            if current_count == 1:
                # First request, set expiry
                await self._redis.expire(rate_limit_key, 60)  # 1 minute window
            
            if current_count > settings.TASK_RATE_LIMIT_PER_MINUTE:
                logger.warning(
                    "Backpressure: Rate limit exceeded",
                    task_name=task_name,
                    current_count=current_count
                )
                await self._redis.decr(rate_limit_key)  # Revert increment
                return True
            
            return False
            
        except Exception as e:
            logger.error("Error checking backpressure", error=str(e))
            return False  # Don't block on error
    
    async def get_task_metrics(self, task_id: str) -> Dict[str, Any]:
        """Get metrics for a specific task"""
        try:
            # Get task result
            result = celery_app.AsyncResult(task_id)
            
            # Get task info from Redis
            task_key = f"task:{task_id}"
            task_data = await self._redis.hgetall(task_key)
            
            return {
                'task_id': task_id,
                'state': result.state,
                'info': result.info,
                'result': result.result if result.ready() else None,
                'metadata': {k.decode(): v.decode() for k, v in task_data.items()} if task_data else {}
            }
        except Exception as e:
            logger.error("Failed to get task metrics", task_id=task_id, error=str(e))
            return {}


class CircuitBreaker:
    """
    Circuit breaker for external API calls
    """
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._failures: Dict[str, int] = {}
        self._last_failure_time: Dict[str, datetime] = {}
        self._state: Dict[str, str] = {}  # 'closed', 'open', 'half_open'
    
    async def call(self, api_name: str, func, *args, **kwargs):
        """
        Execute function with circuit breaker protection
        """
        state = self._get_state(api_name)
        
        if state == 'open':
            # Check if we should try half-open
            if self._should_attempt_reset(api_name):
                self._state[api_name] = 'half_open'
                logger.info(f"Circuit breaker half-open for {api_name}")
            else:
                api_rate_limit_hits.labels(api_name=api_name).inc()
                raise Exception(f"Circuit breaker open for {api_name}")
        
        try:
            result = await func(*args, **kwargs)
            
            # Success - reset failures
            if state == 'half_open':
                logger.info(f"Circuit breaker closed for {api_name}")
            
            self._on_success(api_name)
            api_calls.labels(api_name=api_name, status='success').inc()
            
            return result
            
        except Exception as e:
            self._on_failure(api_name)
            api_calls.labels(api_name=api_name, status='failure').inc()
            
            # Open circuit if threshold reached
            if self._failures.get(api_name, 0) >= self.failure_threshold:
                self._state[api_name] = 'open'
                logger.error(f"Circuit breaker opened for {api_name}")
                api_rate_limit_hits.labels(api_name=api_name).inc()
            
            raise
    
    def _get_state(self, api_name: str) -> str:
        """Get current state for API"""
        return self._state.get(api_name, 'closed')
    
    def _should_attempt_reset(self, api_name: str) -> bool:
        """Check if we should attempt reset"""
        last_failure = self._last_failure_time.get(api_name)
        if last_failure:
            return datetime.utcnow() - last_failure > timedelta(seconds=self.recovery_timeout)
        return False
    
    def _on_success(self, api_name: str):
        """Handle successful call"""
        self._failures[api_name] = 0
        self._state[api_name] = 'closed'
    
    def _on_failure(self, api_name: str):
        """Handle failed call"""
        self._failures[api_name] = self._failures.get(api_name, 0) + 1
        self._last_failure_time[api_name] = datetime.utcnow()


# Global instances
task_monitor = TaskMonitor()
circuit_breaker = CircuitBreaker()

__all__ = ['task_monitor', 'circuit_breaker', 'TaskMonitor', 'CircuitBreaker']