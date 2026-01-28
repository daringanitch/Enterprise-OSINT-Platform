#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.
# Individual use is free. Commercial use requires 3% profit sharing.
# See LICENSE file for details.

"""
Intelligent Caching Service for Enterprise OSINT Platform

Provides Redis-backed caching with:
- Automatic TTL management
- Cache key generation
- Response caching decorators
- Cache invalidation patterns
- Fallback to in-memory cache when Redis unavailable
"""

import json
import hashlib
import logging
import functools
import time
from typing import Any, Optional, Callable, Dict, List, Union
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import os

logger = logging.getLogger(__name__)

# Try to import redis, fallback to in-memory if unavailable
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("Redis not available, using in-memory cache")


class CacheTTL(Enum):
    """Standard cache TTL values"""
    SHORT = 60          # 1 minute - for rapidly changing data
    MEDIUM = 300        # 5 minutes - for moderately stable data
    LONG = 900          # 15 minutes - for stable data
    EXTENDED = 3600     # 1 hour - for rarely changing data
    PERSISTENT = 86400  # 24 hours - for static data


@dataclass
class CacheStats:
    """Cache statistics for monitoring"""
    hits: int = 0
    misses: int = 0
    errors: int = 0
    total_requests: int = 0
    avg_response_time_ms: float = 0.0
    last_reset: datetime = None

    def hit_rate(self) -> float:
        """Calculate cache hit rate"""
        if self.total_requests == 0:
            return 0.0
        return (self.hits / self.total_requests) * 100

    def to_dict(self) -> Dict:
        return {
            'hits': self.hits,
            'misses': self.misses,
            'errors': self.errors,
            'total_requests': self.total_requests,
            'hit_rate_percent': round(self.hit_rate(), 2),
            'avg_response_time_ms': round(self.avg_response_time_ms, 2),
            'last_reset': self.last_reset.isoformat() if self.last_reset else None
        }


class InMemoryCache:
    """Simple in-memory cache fallback when Redis is unavailable"""

    def __init__(self, max_size: int = 1000):
        self._cache: Dict[str, tuple] = {}  # key -> (value, expiry_time)
        self._max_size = max_size

    def get(self, key: str) -> Optional[str]:
        """Get value from cache"""
        if key in self._cache:
            value, expiry = self._cache[key]
            if expiry is None or time.time() < expiry:
                return value
            else:
                # Expired, remove it
                del self._cache[key]
        return None

    def set(self, key: str, value: str, ex: int = None) -> bool:
        """Set value in cache with optional expiry"""
        # Evict oldest entries if at capacity
        if len(self._cache) >= self._max_size:
            # Remove first 10% of entries
            keys_to_remove = list(self._cache.keys())[:self._max_size // 10]
            for k in keys_to_remove:
                del self._cache[k]

        expiry = time.time() + ex if ex else None
        self._cache[key] = (value, expiry)
        return True

    def delete(self, key: str) -> int:
        """Delete key from cache"""
        if key in self._cache:
            del self._cache[key]
            return 1
        return 0

    def exists(self, key: str) -> bool:
        """Check if key exists and is not expired"""
        return self.get(key) is not None

    def keys(self, pattern: str = '*') -> List[str]:
        """Get keys matching pattern (simplified)"""
        if pattern == '*':
            return list(self._cache.keys())
        # Simple prefix matching
        prefix = pattern.rstrip('*')
        return [k for k in self._cache.keys() if k.startswith(prefix)]

    def flushdb(self):
        """Clear all cache entries"""
        self._cache.clear()

    def ping(self) -> bool:
        """Check if cache is available"""
        return True


class CacheService:
    """
    Intelligent caching service with Redis backend and in-memory fallback.

    Features:
    - Automatic key generation from function arguments
    - TTL-based expiration
    - Cache invalidation by pattern
    - Statistics tracking
    - Graceful fallback to in-memory cache
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        """Singleton pattern for cache service"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, redis_url: str = None):
        """Initialize cache service"""
        if self._initialized:
            return

        self._redis_url = redis_url or os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
        self._client = None
        self._stats = CacheStats(last_reset=datetime.utcnow())
        self._prefix = 'osint:'
        self._initialized = True
        self._connect()

    def _connect(self):
        """Establish connection to Redis or fallback to in-memory"""
        if REDIS_AVAILABLE:
            try:
                self._client = redis.from_url(
                    self._redis_url,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    retry_on_timeout=True
                )
                # Test connection
                self._client.ping()
                logger.info(f"Connected to Redis at {self._redis_url}")
            except Exception as e:
                logger.warning(f"Redis connection failed: {e}, using in-memory cache")
                self._client = InMemoryCache()
        else:
            self._client = InMemoryCache()
            logger.info("Using in-memory cache (Redis not available)")

    def _generate_key(self, namespace: str, *args, **kwargs) -> str:
        """Generate cache key from namespace and arguments"""
        # Create a deterministic key from arguments
        key_parts = [str(arg) for arg in args]
        key_parts.extend([f"{k}={v}" for k, v in sorted(kwargs.items())])
        key_data = ':'.join(key_parts)

        # Hash long keys to keep them manageable
        if len(key_data) > 100:
            key_hash = hashlib.md5(key_data.encode()).hexdigest()[:16]
            key_data = key_hash

        return f"{self._prefix}{namespace}:{key_data}"

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        start_time = time.time()
        self._stats.total_requests += 1

        try:
            value = self._client.get(key)
            elapsed = (time.time() - start_time) * 1000

            if value is not None:
                self._stats.hits += 1
                self._update_avg_response_time(elapsed)
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    return value
            else:
                self._stats.misses += 1
                return None

        except Exception as e:
            self._stats.errors += 1
            logger.error(f"Cache get error: {e}")
            return None

    def set(self, key: str, value: Any, ttl: int = CacheTTL.MEDIUM.value) -> bool:
        """Set value in cache with TTL"""
        try:
            # Serialize value to JSON
            if not isinstance(value, str):
                value = json.dumps(value, default=str)

            self._client.set(key, value, ex=ttl)
            return True

        except Exception as e:
            self._stats.errors += 1
            logger.error(f"Cache set error: {e}")
            return False

    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        try:
            return self._client.delete(key) > 0
        except Exception as e:
            logger.error(f"Cache delete error: {e}")
            return False

    def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching pattern"""
        try:
            keys = self._client.keys(f"{self._prefix}{pattern}")
            if keys:
                return sum(self._client.delete(k) for k in keys)
            return 0
        except Exception as e:
            logger.error(f"Cache delete pattern error: {e}")
            return 0

    def invalidate_investigation(self, investigation_id: str) -> int:
        """Invalidate all cache entries for an investigation"""
        return self.delete_pattern(f"*{investigation_id}*")

    def invalidate_all(self) -> bool:
        """Clear entire cache"""
        try:
            self._client.flushdb()
            return True
        except Exception as e:
            logger.error(f"Cache flush error: {e}")
            return False

    def _update_avg_response_time(self, elapsed_ms: float):
        """Update average response time using exponential moving average"""
        alpha = 0.1  # Smoothing factor
        self._stats.avg_response_time_ms = (
            alpha * elapsed_ms + (1 - alpha) * self._stats.avg_response_time_ms
        )

    def get_stats(self) -> Dict:
        """Get cache statistics"""
        return self._stats.to_dict()

    def reset_stats(self):
        """Reset cache statistics"""
        self._stats = CacheStats(last_reset=datetime.utcnow())

    def health_check(self) -> Dict:
        """Check cache health"""
        try:
            start = time.time()
            self._client.ping()
            latency = (time.time() - start) * 1000

            return {
                'status': 'healthy',
                'backend': 'redis' if REDIS_AVAILABLE and not isinstance(self._client, InMemoryCache) else 'memory',
                'latency_ms': round(latency, 2),
                'stats': self.get_stats()
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e),
                'backend': 'unknown'
            }


# Global cache service instance
cache_service = CacheService()


def cached(
    namespace: str,
    ttl: int = CacheTTL.MEDIUM.value,
    key_builder: Callable = None,
    skip_cache_if: Callable = None
):
    """
    Decorator for caching function results.

    Args:
        namespace: Cache key namespace (e.g., 'investigations', 'reports')
        ttl: Time-to-live in seconds
        key_builder: Optional custom key builder function
        skip_cache_if: Optional function to determine if cache should be skipped

    Usage:
        @cached('investigations', ttl=300)
        def get_investigation(inv_id):
            return expensive_operation(inv_id)
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Check if we should skip cache
            if skip_cache_if and skip_cache_if(*args, **kwargs):
                return func(*args, **kwargs)

            # Generate cache key
            if key_builder:
                cache_key = key_builder(*args, **kwargs)
            else:
                cache_key = cache_service._generate_key(namespace, *args, **kwargs)

            # Try to get from cache
            cached_value = cache_service.get(cache_key)
            if cached_value is not None:
                logger.debug(f"Cache hit for {cache_key}")
                return cached_value

            # Execute function and cache result
            result = func(*args, **kwargs)

            # Cache the result
            if result is not None:
                cache_service.set(cache_key, result, ttl=ttl)
                logger.debug(f"Cached result for {cache_key}")

            return result

        return wrapper
    return decorator


def cached_response(
    namespace: str,
    ttl: int = CacheTTL.MEDIUM.value,
    vary_on: List[str] = None
):
    """
    Decorator for caching Flask route responses.

    Args:
        namespace: Cache key namespace
        ttl: Time-to-live in seconds
        vary_on: List of request attributes to vary cache on (e.g., ['user_id'])

    Usage:
        @app.route('/api/investigations')
        @cached_response('investigations_list', ttl=60)
        def list_investigations():
            return jsonify(get_investigations())
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            from flask import request, jsonify

            # Build cache key including varied attributes
            key_parts = [namespace]

            if vary_on:
                for attr in vary_on:
                    if attr == 'user_id' and hasattr(request, 'current_user'):
                        key_parts.append(f"user:{request.current_user.get('user_id', 'anon')}")
                    elif attr == 'query_string':
                        key_parts.append(f"qs:{request.query_string.decode()}")
                    elif attr == 'path':
                        key_parts.append(f"path:{request.path}")

            cache_key = cache_service._generate_key(':'.join(key_parts))

            # Try cache
            cached_value = cache_service.get(cache_key)
            if cached_value is not None:
                # Return cached response with cache header
                response = jsonify(cached_value)
                response.headers['X-Cache'] = 'HIT'
                response.headers['X-Cache-Key'] = cache_key[-32:]  # Last 32 chars
                return response

            # Execute function
            result = func(*args, **kwargs)

            # Cache if it's a successful response
            if hasattr(result, 'get_json'):
                data = result.get_json()
                cache_service.set(cache_key, data, ttl=ttl)
                result.headers['X-Cache'] = 'MISS'

            return result

        return wrapper
    return decorator


def invalidate_cache(namespace: str, *identifiers):
    """
    Decorator to invalidate cache entries after a function executes.

    Usage:
        @invalidate_cache('investigations', 'inv_id')
        def update_investigation(inv_id, data):
            # Update logic
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)

            # Invalidate cache entries
            for identifier in identifiers:
                if identifier in kwargs:
                    cache_service.delete_pattern(f"{namespace}*{kwargs[identifier]}*")
                elif args:
                    # Try to get from positional args based on function signature
                    import inspect
                    sig = inspect.signature(func)
                    params = list(sig.parameters.keys())
                    if identifier in params:
                        idx = params.index(identifier)
                        if idx < len(args):
                            cache_service.delete_pattern(f"{namespace}*{args[idx]}*")

            return result
        return wrapper
    return decorator
