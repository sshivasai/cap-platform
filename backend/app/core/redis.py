"""
Redis configuration and utilities for CAP Platform.

This module provides:
- Redis connection management with connection pooling
- Session management and caching utilities
- Rate limiting implementation
- Pub/Sub messaging for real-time features
- Distributed locking mechanisms
- Cache decorators and utilities

Designed for production scalability with proper error handling,
connection pooling, and monitoring capabilities.
"""

import asyncio
import json
import pickle
import hashlib
from typing import Any, Dict, List, Optional, Union, Callable, TypeVar, Generic
from datetime import datetime, timedelta
from functools import wraps
from contextlib import asynccontextmanager

import redis.asyncio as redis
from redis.asyncio.lock import Lock as RedisLock
from redis.exceptions import RedisError, ConnectionError, TimeoutError

from app.core.config import settings
from app.utils.logging import get_logger

logger = get_logger(__name__)

# Type variable for generic cache decorator
T = TypeVar('T')


# ================================
# Redis Manager Class
# ================================

class RedisManager:
    """
    Centralized Redis connection and operations manager.
    
    Provides high-level interface for caching, session management,
    rate limiting, pub/sub messaging, and distributed locking.
    """
    
    def __init__(self):
        self._client: Optional[redis.Redis] = None
        self._pubsub_client: Optional[redis.Redis] = None
        self._connection_pool: Optional[redis.ConnectionPool] = None
        self._initialized = False
    
    async def initialize(self):
        """Initialize Redis connection with connection pooling."""
        if self._initialized:
            return
        
        logger.info("Initializing Redis connection...")
        
        try:
            # Configure connection pool
            pool_config = {
                "host": settings.REDIS_HOST,
                "port": settings.REDIS_PORT,
                "db": settings.REDIS_DB,
                "decode_responses": True,
                "max_connections": settings.REDIS_POOL_SIZE,
                "retry_on_timeout": True,
                "socket_connect_timeout": 5,
                "socket_timeout": 5,
                "health_check_interval": 30,
            }
            
            if settings.REDIS_PASSWORD:
                pool_config["password"] = settings.REDIS_PASSWORD
            
            # Create connection pool
            self._connection_pool = redis.ConnectionPool(**pool_config)
            
            # Create Redis clients
            self._client = redis.Redis(connection_pool=self._connection_pool)
            self._pubsub_client = redis.Redis(connection_pool=self._connection_pool)
            
            # Test connection
            await self._test_connection()
            
            self._initialized = True
            logger.info("Redis connection initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Redis: {e}")
            raise
    
    async def _test_connection(self):
        """Test Redis connection."""
        try:
            pong = await self._client.ping()
            if not pong:
                raise Exception("Redis ping returned False")
            logger.debug("Redis connection test successful")
        except Exception as e:
            logger.error(f"Redis connection test failed: {e}")
            raise
    
    @property
    def client(self) -> redis.Redis:
        """Get Redis client."""
        if not self._initialized or not self._client:
            raise RuntimeError("Redis not initialized. Call initialize() first.")
        return self._client
    
    @property
    def pubsub_client(self) -> redis.Redis:
        """Get Redis pub/sub client."""
        if not self._initialized or not self._pubsub_client:
            raise RuntimeError("Redis not initialized. Call initialize() first.")
        return self._pubsub_client
    
    async def close(self):
        """Close Redis connections."""
        logger.info("Closing Redis connections...")
        
        if self._client:
            await self._client.aclose()
        
        if self._pubsub_client:
            await self._pubsub_client.aclose()
        
        if self._connection_pool:
            await self._connection_pool.aclose()
        
        self._initialized = False
        logger.info("Redis connections closed")
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform Redis health check.
        
        Returns:
            Dict containing health status and connection info
        """
        try:
            # Test basic connectivity
            start_time = datetime.utcnow()
            pong = await self._client.ping()
            response_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            if not pong:
                return {
                    "status": "unhealthy",
                    "error": "Ping returned False",
                    "response_time_ms": response_time
                }
            
            # Get Redis info
            info = await self._client.info()
            
            return {
                "status": "healthy",
                "response_time_ms": response_time,
                "redis_version": info.get("redis_version"),
                "connected_clients": info.get("connected_clients"),
                "used_memory_human": info.get("used_memory_human"),
                "total_commands_processed": info.get("total_commands_processed"),
            }
            
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e)
            }


# ================================
# Cache Utilities
# ================================

class CacheManager:
    """
    High-level cache management with TTL, serialization, and invalidation.
    """
    
    def __init__(self, redis_manager: RedisManager):
        self.redis = redis_manager
        self.default_ttl = 3600  # 1 hour default TTL
    
    def _make_key(self, key: str, namespace: str = "cache") -> str:
        """Generate namespaced cache key."""
        prefix = getattr(settings, f"REDIS_{namespace.upper()}_PREFIX", f"cap:{namespace}:")
        return f"{prefix}{key}"
    
    async def get(self, key: str, default: Any = None, namespace: str = "cache") -> Any:
        """
        Get value from cache with automatic deserialization.
        
        Args:
            key: Cache key
            default: Default value if key not found
            namespace: Cache namespace
            
        Returns:
            Cached value or default
        """
        try:
            cache_key = self._make_key(key, namespace)
            value = await self.redis.client.get(cache_key)
            
            if value is None:
                return default
            
            # Try to deserialize JSON first, fallback to pickle
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                try:
                    return pickle.loads(value.encode('latin1'))
                except Exception:
                    return value  # Return as string if all else fails
                    
        except RedisError as e:
            logger.error(f"Cache get error for key {key}: {e}")
            return default
    
    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        namespace: str = "cache"
    ) -> bool:
        """
        Set value in cache with automatic serialization.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds
            namespace: Cache namespace
            
        Returns:
            True if successful, False otherwise
        """
        try:
            cache_key = self._make_key(key, namespace)
            ttl = ttl or self.default_ttl
            
            # Serialize value
            if isinstance(value, (dict, list, tuple, bool)) or value is None:
                serialized = json.dumps(value, default=str)
            elif isinstance(value, (str, int, float)):
                serialized = value
            else:
                # Use pickle for complex objects
                serialized = pickle.dumps(value).decode('latin1')
            
            # Set with TTL
            result = await self.redis.client.setex(cache_key, ttl, serialized)
            return result
            
        except RedisError as e:
            logger.error(f"Cache set error for key {key}: {e}")
            return False
    
    async def delete(self, key: str, namespace: str = "cache") -> bool:
        """
        Delete key from cache.
        
        Args:
            key: Cache key to delete
            namespace: Cache namespace
            
        Returns:
            True if key was deleted, False otherwise
        """
        try:
            cache_key = self._make_key(key, namespace)
            result = await self.redis.client.delete(cache_key)
            return bool(result)
        except RedisError as e:
            logger.error(f"Cache delete error for key {key}: {e}")
            return False
    
    async def exists(self, key: str, namespace: str = "cache") -> bool:
        """Check if key exists in cache."""
        try:
            cache_key = self._make_key(key, namespace)
            result = await self.redis.client.exists(cache_key)
            return bool(result)
        except RedisError as e:
            logger.error(f"Cache exists error for key {key}: {e}")
            return False
    
    async def increment(self, key: str, amount: int = 1, namespace: str = "cache") -> int:
        """Increment numeric value in cache."""
        try:
            cache_key = self._make_key(key, namespace)
            result = await self.redis.client.incrby(cache_key, amount)
            return result
        except RedisError as e:
            logger.error(f"Cache increment error for key {key}: {e}")
            return 0
    
    async def expire(self, key: str, ttl: int, namespace: str = "cache") -> bool:
        """Set expiration time for existing key."""
        try:
            cache_key = self._make_key(key, namespace)
            result = await self.redis.client.expire(cache_key, ttl)
            return bool(result)
        except RedisError as e:
            logger.error(f"Cache expire error for key {key}: {e}")
            return False
    
    async def clear_namespace(self, namespace: str) -> int:
        """Clear all keys in a namespace."""
        try:
            pattern = self._make_key("*", namespace)
            keys = await self.redis.client.keys(pattern)
            if keys:
                result = await self.redis.client.delete(*keys)
                return result
            return 0
        except RedisError as e:
            logger.error(f"Cache clear namespace error for {namespace}: {e}")
            return 0


# ================================
# Session Management
# ================================

class SessionManager:
    """
    Redis-based session management for user authentication.
    """
    
    def __init__(self, redis_manager: RedisManager):
        self.redis = redis_manager
        self.cache = CacheManager(redis_manager)
        self.session_ttl = settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600  # Convert days to seconds
    
    async def create_session(
        self,
        user_id: str,
        session_data: Dict[str, Any],
        session_id: Optional[str] = None
    ) -> str:
        """
        Create new user session.
        
        Args:
            user_id: User ID
            session_data: Session data to store
            session_id: Optional custom session ID
            
        Returns:
            Session ID
        """
        if not session_id:
            import uuid
            session_id = str(uuid.uuid4())
        
        session_key = f"session:{session_id}"
        
        # Add metadata to session data
        session_data.update({
            "user_id": user_id,
            "created_at": datetime.utcnow().isoformat(),
            "last_accessed": datetime.utcnow().isoformat(),
        })
        
        # Store session
        await self.cache.set(session_key, session_data, ttl=self.session_ttl, namespace="session")
        
        # Add to user's session list
        user_sessions_key = f"user_sessions:{user_id}"
        await self.redis.client.sadd(user_sessions_key, session_id)
        await self.redis.client.expire(user_sessions_key, self.session_ttl)
        
        logger.debug(f"Created session {session_id} for user {user_id}")
        return session_id
    
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data."""
        session_data = await self.cache.get(f"session:{session_id}", namespace="session")
        
        if session_data:
            # Update last accessed time
            session_data["last_accessed"] = datetime.utcnow().isoformat()
            await self.cache.set(f"session:{session_id}", session_data, ttl=self.session_ttl, namespace="session")
        
        return session_data
    
    async def update_session(self, session_id: str, data: Dict[str, Any]) -> bool:
        """Update session data."""
        session_data = await self.get_session(session_id)
        if not session_data:
            return False
        
        session_data.update(data)
        session_data["last_accessed"] = datetime.utcnow().isoformat()
        
        return await self.cache.set(f"session:{session_id}", session_data, ttl=self.session_ttl, namespace="session")
    
    async def delete_session(self, session_id: str) -> bool:
        """Delete session."""
        session_data = await self.cache.get(f"session:{session_id}", namespace="session")
        
        if session_data and "user_id" in session_data:
            # Remove from user's session list
            user_sessions_key = f"user_sessions:{session_data['user_id']}"
            await self.redis.client.srem(user_sessions_key, session_id)
        
        return await self.cache.delete(f"session:{session_id}", namespace="session")
    
    async def get_user_sessions(self, user_id: str) -> List[str]:
        """Get all session IDs for a user."""
        try:
            user_sessions_key = f"user_sessions:{user_id}"
            sessions = await self.redis.client.smembers(user_sessions_key)
            return list(sessions) if sessions else []
        except RedisError as e:
            logger.error(f"Error getting user sessions for {user_id}: {e}")
            return []
    
    async def delete_all_user_sessions(self, user_id: str) -> int:
        """Delete all sessions for a user."""
        sessions = await self.get_user_sessions(user_id)
        count = 0
        
        for session_id in sessions:
            if await self.delete_session(session_id):
                count += 1
        
        # Clear user sessions set
        user_sessions_key = f"user_sessions:{user_id}"
        await self.redis.client.delete(user_sessions_key)
        
        logger.info(f"Deleted {count} sessions for user {user_id}")
        return count


# ================================
# Rate Limiting
# ================================

class RateLimiter:
    """
    Redis-based rate limiting with sliding window and token bucket algorithms.
    """
    
    def __init__(self, redis_manager: RedisManager):
        self.redis = redis_manager
        self.cache = CacheManager(redis_manager)
    
    async def is_allowed(
        self,
        key: str,
        limit: int,
        window_seconds: int,
        algorithm: str = "sliding_window"
    ) -> tuple[bool, Dict[str, Any]]:
        """
        Check if request is allowed based on rate limit.
        
        Args:
            key: Rate limit key (e.g., IP address, user ID)
            limit: Maximum number of requests
            window_seconds: Time window in seconds
            algorithm: Rate limiting algorithm ('sliding_window' or 'token_bucket')
            
        Returns:
            Tuple of (is_allowed, info_dict)
        """
        if algorithm == "sliding_window":
            return await self._sliding_window_check(key, limit, window_seconds)
        elif algorithm == "token_bucket":
            return await self._token_bucket_check(key, limit, window_seconds)
        else:
            raise ValueError(f"Unknown rate limiting algorithm: {algorithm}")
    
    async def _sliding_window_check(
        self,
        key: str,
        limit: int,
        window_seconds: int
    ) -> tuple[bool, Dict[str, Any]]:
        """Sliding window rate limiting implementation."""
        rate_limit_key = self._make_key(key, "rate_limit")
        current_time = int(datetime.utcnow().timestamp())
        window_start = current_time - window_seconds
        
        try:
            pipe = self.redis.client.pipeline()
            
            # Remove old entries
            pipe.zremrangebyscore(rate_limit_key, 0, window_start)
            
            # Count current requests in window
            pipe.zcard(rate_limit_key)
            
            # Add current request
            pipe.zadd(rate_limit_key, {str(current_time): current_time})
            
            # Set expiration
            pipe.expire(rate_limit_key, window_seconds)
            
            results = await pipe.execute()
            current_requests = results[1]  # Count from zcard
            
            is_allowed = current_requests < limit
            
            if not is_allowed:
                # Remove the request we just added since it's not allowed
                await self.redis.client.zrem(rate_limit_key, str(current_time))
            
            return is_allowed, {
                "limit": limit,
                "remaining": max(0, limit - current_requests - (1 if is_allowed else 0)),
                "reset_time": current_time + window_seconds,
                "retry_after": None if is_allowed else window_seconds
            }
            
        except RedisError as e:
            logger.error(f"Rate limit check error for key {key}: {e}")
            # Fail open - allow request if Redis is down
            return True, {"error": str(e)}
    
    async def _token_bucket_check(
        self,
        key: str,
        limit: int,
        refill_rate: int
    ) -> tuple[bool, Dict[str, Any]]:
        """Token bucket rate limiting implementation."""
        bucket_key = self._make_key(key, "token_bucket")
        current_time = datetime.utcnow().timestamp()
        
        try:
            # Get current bucket state
            bucket_data = await self.cache.get(bucket_key, namespace="rate_limit")
            
            if bucket_data is None:
                # Initialize bucket
                bucket_data = {
                    "tokens": limit,
                    "last_refill": current_time
                }
            
            # Calculate tokens to add based on time elapsed
            time_elapsed = current_time - bucket_data["last_refill"]
            tokens_to_add = int(time_elapsed * refill_rate)
            
            # Refill bucket
            bucket_data["tokens"] = min(limit, bucket_data["tokens"] + tokens_to_add)
            bucket_data["last_refill"] = current_time
            
            # Check if request is allowed
            is_allowed = bucket_data["tokens"] > 0
            
            if is_allowed:
                bucket_data["tokens"] -= 1
            
            # Save bucket state
            await self.cache.set(bucket_key, bucket_data, ttl=3600, namespace="rate_limit")
            
            return is_allowed, {
                "limit": limit,
                "remaining": bucket_data["tokens"],
                "reset_time": None,
                "retry_after": None if is_allowed else 1.0 / refill_rate
            }
            
        except RedisError as e:
            logger.error(f"Token bucket check error for key {key}: {e}")
            return True, {"error": str(e)}
    
    def _make_key(self, key: str, prefix: str) -> str:
        """Generate rate limit key."""
        return f"{settings.REDIS_RATE_LIMIT_PREFIX}{prefix}:{key}"


# ================================
# Pub/Sub Messaging
# ================================

class PubSubManager:
    """
    Redis pub/sub messaging for real-time features.
    """
    
    def __init__(self, redis_manager: RedisManager):
        self.redis = redis_manager
        self._subscribers: Dict[str, List[Callable]] = {}
    
    async def publish(self, channel: str, message: Dict[str, Any]) -> int:
        """
        Publish message to channel.
        
        Args:
            channel: Channel name
            message: Message data
            
        Returns:
            Number of subscribers that received the message
        """
        try:
            serialized_message = json.dumps(message, default=str)
            result = await self.redis.pubsub_client.publish(channel, serialized_message)
            logger.debug(f"Published message to {channel}: {result} subscribers")
            return result
        except Exception as e:
            logger.error(f"Error publishing to {channel}: {e}")
            return 0
    
    async def subscribe(self, channel: str, callback: Callable[[str, Dict[str, Any]], None]):
        """
        Subscribe to channel with callback.
        
        Args:
            channel: Channel name to subscribe to
            callback: Function to call when message is received
        """
        if channel not in self._subscribers:
            self._subscribers[channel] = []
        
        self._subscribers[channel].append(callback)
        logger.info(f"Subscribed to channel: {channel}")
    
    async def start_listening(self):
        """Start listening for pub/sub messages."""
        if not self._subscribers:
            logger.warning("No subscribers registered")
            return
        
        pubsub = self.redis.pubsub_client.pubsub()
        
        try:
            # Subscribe to all registered channels
            await pubsub.subscribe(*self._subscribers.keys())
            logger.info(f"Started listening on channels: {list(self._subscribers.keys())}")
            
            async for message in pubsub.listen():
                if message["type"] == "message":
                    channel = message["channel"]
                    
                    try:
                        # Deserialize message
                        data = json.loads(message["data"])
                        
                        # Call all callbacks for this channel
                        for callback in self._subscribers.get(channel, []):
                            try:
                                await callback(channel, data)
                            except Exception as e:
                                logger.error(f"Error in callback for {channel}: {e}")
                    
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to decode message from {channel}: {e}")
                    
        except Exception as e:
            logger.error(f"Error in pub/sub listener: {e}")
        finally:
            await pubsub.close()


# ================================
# Distributed Locking
# ================================

class DistributedLock:
    """
    Redis-based distributed locking mechanism.
    """
    
    def __init__(self, redis_manager: RedisManager, name: str, timeout: int = 60):
        self.redis = redis_manager
        self.name = name
        self.timeout = timeout
        self._lock: Optional[RedisLock] = None
    
    async def __aenter__(self):
        """Acquire lock."""
        lock_key = f"{settings.REDIS_LOCK_PREFIX}{self.name}"
        self._lock = RedisLock(
            self.redis.client,
            lock_key,
            timeout=self.timeout,
            blocking=True,
            blocking_timeout=self.timeout
        )
        
        acquired = await self._lock.acquire()
        if not acquired:
            raise TimeoutError(f"Failed to acquire lock: {self.name}")
        
        logger.debug(f"Acquired distributed lock: {self.name}")
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Release lock."""
        if self._lock:
            await self._lock.release()
            logger.debug(f"Released distributed lock: {self.name}")


# ================================
# Cache Decorators
# ================================

def cache_result(
    ttl: int = 3600,
    key_prefix: str = "",
    namespace: str = "cache"
):
    """
    Decorator to cache function results.
    
    Args:
        ttl: Time to live in seconds
        key_prefix: Prefix for cache key
        namespace: Cache namespace
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            # Generate cache key from function name and arguments
            key_parts = [key_prefix, func.__name__]
            
            # Add args to key
            if args:
                args_str = "_".join(str(arg) for arg in args)
                key_parts.append(hashlib.md5(args_str.encode()).hexdigest()[:8])
            
            # Add kwargs to key
            if kwargs:
                kwargs_str = "_".join(f"{k}={v}" for k, v in sorted(kwargs.items()))
                key_parts.append(hashlib.md5(kwargs_str.encode()).hexdigest()[:8])
            
            cache_key = "_".join(filter(None, key_parts))
            
            # Try to get from cache
            cached_result = await cache_manager.get(cache_key, namespace=namespace)
            if cached_result is not None:
                logger.debug(f"Cache hit for key: {cache_key}")
                return cached_result
            
            # Execute function and cache result
            result = await func(*args, **kwargs)
            await cache_manager.set(cache_key, result, ttl=ttl, namespace=namespace)
            logger.debug(f"Cached result for key: {cache_key}")
            
            return result
        
        return wrapper
    return decorator


def invalidate_cache(key_pattern: str, namespace: str = "cache"):
    """
    Decorator to invalidate cache entries matching pattern.
    
    Args:
        key_pattern: Pattern to match cache keys (supports wildcards)
        namespace: Cache namespace
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            result = await func(*args, **kwargs)
            
            # Invalidate matching cache entries
            try:
                pattern = cache_manager._make_key(key_pattern, namespace)
                keys = await redis_manager.client.keys(pattern)
                if keys:
                    await redis_manager.client.delete(*keys)
                    logger.debug(f"Invalidated {len(keys)} cache entries matching: {pattern}")
            except Exception as e:
                logger.error(f"Error invalidating cache: {e}")
            
            return result
        
        return wrapper
    return decorator


# ================================
# Global Instances
# ================================

# Global Redis manager instance
redis_manager = RedisManager()

# Global utility instances
cache_manager = CacheManager(redis_manager)
session_manager = SessionManager(redis_manager)
rate_limiter = RateLimiter(redis_manager)
pubsub_manager = PubSubManager(redis_manager)


# ================================
# Convenience Functions
# ================================

async def get_redis() -> redis.Redis:
    """Get Redis client for dependency injection."""
    return redis_manager.client


async def get_cache() -> CacheManager:
    """Get cache manager for dependency injection."""
    return cache_manager


async def get_session_manager() -> SessionManager:
    """Get session manager for dependency injection."""
    return session_manager


async def get_rate_limiter() -> RateLimiter:
    """Get rate limiter for dependency injection."""
    return rate_limiter


# ================================
# Rate Limiting Utilities
# ================================

async def check_rate_limit(
    identifier: str,
    limit: int,
    window_seconds: int,
    rate_type: str = "api"
) -> tuple[bool, Dict[str, Any]]:
    """
    Convenience function for rate limiting checks.
    
    Args:
        identifier: Unique identifier (IP, user ID, etc.)
        limit: Request limit
        window_seconds: Time window
        rate_type: Type of rate limit for key namespacing
        
    Returns:
        Tuple of (is_allowed, rate_limit_info)
    """
    key = f"{rate_type}:{identifier}"
    return await rate_limiter.is_allowed(key, limit, window_seconds)


# ================================
# Credit System Cache Utilities
# ================================

class CreditCacheManager:
    """
    Specialized cache manager for credit system operations.
    """
    
    def __init__(self, cache_manager: CacheManager):
        self.cache = cache_manager
        self.namespace = "credits"
    
    async def get_user_credits(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get cached user credit information."""
        return await self.cache.get(f"user:{user_id}", namespace=self.namespace)
    
    async def set_user_credits(
        self,
        user_id: str,
        credit_data: Dict[str, Any],
        ttl: int = 300  # 5 minutes default
    ) -> bool:
        """Cache user credit information."""
        return await self.cache.set(f"user:{user_id}", credit_data, ttl=ttl, namespace=self.namespace)
    
    async def increment_usage(
        self,
        user_id: str,
        amount: float,
        usage_type: str
    ) -> float:
        """Increment usage counter for user."""
        key = f"usage:{usage_type}:{user_id}:{datetime.utcnow().strftime('%Y-%m-%d')}"
        return await self.cache.increment(key, int(amount * 100), namespace=self.namespace) / 100
    
    async def get_daily_usage(self, user_id: str, usage_type: str) -> float:
        """Get daily usage for user."""
        key = f"usage:{usage_type}:{user_id}:{datetime.utcnow().strftime('%Y-%m-%d')}"
        result = await self.cache.get(key, default=0, namespace=self.namespace)
        return float(result) / 100 if result else 0.0


# Global credit cache manager
credit_cache = CreditCacheManager(cache_manager)


# ================================
# Initialization Function
# ================================

async def init_redis():
    """Initialize Redis connections and managers."""
    logger.info("Initializing Redis...")
    await redis_manager.initialize()
    logger.info("Redis initialization completed")


# ================================
# Cleanup Function
# ================================

async def cleanup_redis():
    """Cleanup Redis connections."""
    logger.info("Cleaning up Redis connections...")
    await redis_manager.close()
    logger.info("Redis cleanup completed")