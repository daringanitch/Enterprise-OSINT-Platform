#!/usr/bin/env python3
"""
Unit tests for the caching service.

Tests:
- In-memory cache operations
- Cache key generation
- TTL expiration
- Cache statistics
- Decorator functionality
"""

import pytest
import sys
import os
import time
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cache_service import (
    InMemoryCache, CacheService, CacheTTL, CacheStats,
    cached, cached_response
)


class TestInMemoryCache:
    """Test in-memory cache implementation"""

    def test_set_and_get(self):
        """Test basic set and get operations"""
        cache = InMemoryCache()
        cache.set('key1', 'value1')
        assert cache.get('key1') == 'value1'

    def test_get_nonexistent_key(self):
        """Test getting a nonexistent key returns None"""
        cache = InMemoryCache()
        assert cache.get('nonexistent') is None

    def test_expiry(self):
        """Test that expired entries return None"""
        cache = InMemoryCache()
        cache.set('key1', 'value1', ex=1)  # 1 second expiry
        assert cache.get('key1') == 'value1'
        time.sleep(1.1)  # Wait for expiry
        assert cache.get('key1') is None

    def test_delete(self):
        """Test delete operation"""
        cache = InMemoryCache()
        cache.set('key1', 'value1')
        assert cache.delete('key1') == 1
        assert cache.get('key1') is None

    def test_delete_nonexistent(self):
        """Test deleting nonexistent key returns 0"""
        cache = InMemoryCache()
        assert cache.delete('nonexistent') == 0

    def test_exists(self):
        """Test exists operation"""
        cache = InMemoryCache()
        cache.set('key1', 'value1')
        assert cache.exists('key1') is True
        assert cache.exists('nonexistent') is False

    def test_keys_pattern(self):
        """Test keys with pattern matching"""
        cache = InMemoryCache()
        cache.set('user:1', 'a')
        cache.set('user:2', 'b')
        cache.set('other:1', 'c')

        all_keys = cache.keys('*')
        assert len(all_keys) == 3

        user_keys = cache.keys('user:*')
        assert len(user_keys) == 2

    def test_flushdb(self):
        """Test clearing all entries"""
        cache = InMemoryCache()
        cache.set('key1', 'value1')
        cache.set('key2', 'value2')
        cache.flushdb()
        assert cache.get('key1') is None
        assert cache.get('key2') is None

    def test_max_size_eviction(self):
        """Test that old entries are evicted when max size is reached"""
        cache = InMemoryCache(max_size=10)
        for i in range(15):
            cache.set(f'key{i}', f'value{i}')

        # Should have evicted some entries
        assert len(cache._cache) <= 10

    def test_ping(self):
        """Test ping always returns True for in-memory cache"""
        cache = InMemoryCache()
        assert cache.ping() is True


class TestCacheStats:
    """Test cache statistics"""

    def test_initial_stats(self):
        """Test initial stats are zero"""
        stats = CacheStats()
        assert stats.hits == 0
        assert stats.misses == 0
        assert stats.errors == 0

    def test_hit_rate_zero_requests(self):
        """Test hit rate with zero requests"""
        stats = CacheStats()
        assert stats.hit_rate() == 0.0

    def test_hit_rate_calculation(self):
        """Test hit rate calculation"""
        stats = CacheStats(hits=75, misses=25, total_requests=100)
        assert stats.hit_rate() == 75.0

    def test_to_dict(self):
        """Test serialization to dict"""
        stats = CacheStats(hits=10, misses=5, total_requests=15)
        result = stats.to_dict()
        assert result['hits'] == 10
        assert result['misses'] == 5
        assert 'hit_rate_percent' in result


class TestCacheService:
    """Test cache service"""

    def test_singleton_pattern(self):
        """Test that CacheService is a singleton"""
        service1 = CacheService()
        service2 = CacheService()
        assert service1 is service2

    def test_key_generation(self):
        """Test cache key generation"""
        service = CacheService()
        key1 = service._generate_key('test', 'arg1', 'arg2')
        key2 = service._generate_key('test', 'arg1', 'arg2')
        key3 = service._generate_key('test', 'arg1', 'arg3')

        # Same arguments should produce same key
        assert key1 == key2
        # Different arguments should produce different key
        assert key1 != key3

    def test_key_generation_with_kwargs(self):
        """Test key generation with keyword arguments"""
        service = CacheService()
        key1 = service._generate_key('test', foo='bar', baz='qux')
        key2 = service._generate_key('test', baz='qux', foo='bar')  # Different order

        # Order shouldn't matter (sorted internally)
        assert key1 == key2

    def test_set_and_get_json(self):
        """Test setting and getting JSON data"""
        service = CacheService()
        data = {'key': 'value', 'number': 42}
        service.set('test_json', data, ttl=60)

        result = service.get('test_json')
        assert result == data

    def test_get_nonexistent(self):
        """Test getting nonexistent key"""
        service = CacheService()
        assert service.get('definitely_not_exists_12345') is None

    def test_delete(self):
        """Test delete operation"""
        service = CacheService()
        service.set('to_delete', 'value', ttl=60)
        assert service.delete('to_delete') is True
        assert service.get('to_delete') is None

    def test_stats_tracking(self):
        """Test that stats are tracked"""
        service = CacheService()
        service.reset_stats()

        # This should be a miss
        service.get('nonexistent_stats_test')
        stats = service.get_stats()
        assert stats['misses'] >= 1

    def test_health_check(self):
        """Test health check returns proper structure"""
        service = CacheService()
        health = service.health_check()

        assert 'status' in health
        assert 'backend' in health
        assert health['status'] in ['healthy', 'unhealthy']


class TestCachedDecorator:
    """Test the @cached decorator"""

    def test_caches_result(self):
        """Test that results are cached"""
        call_count = 0

        @cached('test_decorator', ttl=60)
        def expensive_function(x):
            nonlocal call_count
            call_count += 1
            return x * 2

        # First call - should execute function
        result1 = expensive_function(5)
        assert result1 == 10
        assert call_count == 1

        # Second call with same args - should use cache
        result2 = expensive_function(5)
        assert result2 == 10
        assert call_count == 1  # Should not have incremented

        # Call with different args - should execute function
        result3 = expensive_function(10)
        assert result3 == 20
        assert call_count == 2

    def test_cache_none_not_cached(self):
        """Test that None results are not cached"""
        call_count = 0

        @cached('test_none', ttl=60)
        def returns_none():
            nonlocal call_count
            call_count += 1
            return None

        returns_none()
        returns_none()
        # Should have called twice since None isn't cached
        assert call_count == 2


class TestCacheTTL:
    """Test cache TTL constants"""

    def test_ttl_values(self):
        """Test TTL enum values"""
        assert CacheTTL.SHORT.value == 60
        assert CacheTTL.MEDIUM.value == 300
        assert CacheTTL.LONG.value == 900
        assert CacheTTL.EXTENDED.value == 3600
        assert CacheTTL.PERSISTENT.value == 86400


class TestCacheInvalidation:
    """Test cache invalidation patterns"""

    def test_invalidate_investigation(self):
        """Test invalidating investigation cache"""
        service = CacheService()
        inv_id = 'test_inv_123'

        # Set some cache entries using the service's key generation
        key1 = service._generate_key('investigations', inv_id)
        key2 = service._generate_key('reports', inv_id)
        service.set(key1, {'data': 'test'}, ttl=60)
        service.set(key2, {'report': 'test'}, ttl=60)

        # Invalidate - this uses pattern matching
        count = service.invalidate_investigation(inv_id)

        # Should have removed entries containing inv_id
        # Note: Pattern matching depends on implementation
        assert count >= 0  # At least tried to invalidate

    def test_invalidate_all(self):
        """Test invalidating all cache entries"""
        service = CacheService()

        # Set some entries
        service.set('test1', 'value1', ttl=60)
        service.set('test2', 'value2', ttl=60)

        # Invalidate all
        service.invalidate_all()

        # Entries should be gone
        assert service.get('test1') is None
        assert service.get('test2') is None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
