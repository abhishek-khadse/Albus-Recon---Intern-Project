"""Custom rate limiting middleware."""
from fastapi import Request, HTTPException, status
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import time
import redis
from typing import Dict, Any
from collections import defaultdict

from core.logging import get_logger

logger = get_logger(__name__)


class CustomLimiter:
    """Custom rate limiter with Redis backend and sliding window."""
    
    def __init__(self, redis_url: str = None):
        self.redis_client = None
        self.memory_store = defaultdict(list)  # Fallback in-memory store
        
        if redis_url:
            try:
                self.redis_client = redis.from_url(redis_url, decode_responses=True)
                self.redis_client.ping()
                logger.info("Redis rate limiter initialized")
            except Exception as e:
                logger.warning(f"Redis not available, using in-memory rate limiting: {e}")
        else:
            logger.info("Using in-memory rate limiting")
    
    def is_allowed(self, key: str, limit: int, window: int) -> tuple[bool, Dict[str, Any]]:
        """
        Check if request is allowed based on rate limit.
        
        Args:
            key: Rate limit key (usually IP address)
            limit: Number of requests allowed
            window: Time window in seconds
            
        Returns:
            Tuple of (allowed, info_dict)
        """
        now = time.time()
        window_start = now - window
        
        if self.redis_client:
            return self._redis_check(key, limit, window, now)
        else:
            return self._memory_check(key, limit, window, window_start, now)
    
    def _redis_check(self, key: str, limit: int, window: int, now: float) -> tuple[bool, Dict[str, Any]]:
        """Check rate limit using Redis with sliding window."""
        try:
            pipe = self.redis_client.pipeline()
            
            # Remove old entries
            pipe.zremrangebyscore(key, 0, now - window)
            
            # Count current requests
            pipe.zcard(key)
            
            # Add current request
            pipe.zadd(key, {str(now): now})
            
            # Set expiration
            pipe.expire(key, window)
            
            results = pipe.execute()
            current_requests = results[1]
            
            allowed = current_requests < limit
            
            info = {
                "limit": limit,
                "remaining": max(0, limit - current_requests - (1 if allowed else 0)),
                "reset_time": now + window,
                "retry_after": window if not allowed else 0
            }
            
            return allowed, info
        
        except Exception as e:
            logger.error(f"Redis rate limit check failed: {e}")
            # Fallback to allow request if Redis fails
            return True, {"limit": limit, "remaining": limit - 1}
    
    def _memory_check(self, key: str, limit: int, window: int, window_start: float, now: float) -> tuple[bool, Dict[str, Any]]:
        """Check rate limit using in-memory storage."""
        # Clean old entries
        self.memory_store[key] = [
            timestamp for timestamp in self.memory_store[key]
            if timestamp > window_start
        ]
        
        current_requests = len(self.memory_store[key])
        allowed = current_requests < limit
        
        if allowed:
            self.memory_store[key].append(now)
        
        info = {
            "limit": limit,
            "remaining": max(0, limit - current_requests - (1 if allowed else 0)),
            "reset_time": now + window,
            "retry_after": window if not allowed else 0
        }
        
        return allowed, info


class RateLimitMiddleware:
    """Custom rate limiting middleware with different limits per endpoint."""
    
    def __init__(self, app, redis_url: str = None):
        self.app = app
        self.limiter = CustomLimiter(redis_url)
        
        # Rate limit configurations
        self.rate_limits = {
            # Global limits
            "default": {"limit": 100, "window": 60},  # 100 requests per minute
            
            # Authentication endpoints (stricter)
            "/api/auth/login": {"limit": 5, "window": 300},  # 5 requests per 5 minutes
            "/api/auth/register": {"limit": 3, "window": 300},  # 3 requests per 5 minutes
            "/api/auth/refresh": {"limit": 10, "window": 60},  # 10 requests per minute
            
            # Scanning endpoints (moderate)
            "/api/scans": {"limit": 20, "window": 60},  # 20 requests per minute
            "/api/recon": {"limit": 30, "window": 60},  # 30 requests per minute
            
            # Tools endpoints (stricter due to external API calls)
            "/api/tools/subdomains": {"limit": 10, "window": 60},  # 10 requests per minute
            "/api/tools/port-scan": {"limit": 5, "window": 60},  # 5 requests per minute
            
            # Vulnerability endpoints (higher limit for internal use)
            "/api/vulnerabilities": {"limit": 200, "window": 60},  # 200 requests per minute
        }
    
    async def __call__(self, scope, receive, send):
        """ASGI callable."""
        if scope["type"] == "http":
            request = Request(scope, receive)
            
            # Get rate limit config for this path
            path = request.url.path
            rate_config = self._get_rate_config(path)
            
            # Get client identifier
            client_id = self._get_client_id(request)
            
            # Check rate limit
            allowed, info = self.limiter.is_allowed(
                f"{client_id}:{path}",
                rate_config["limit"],
                rate_config["window"]
            )
            
            if not allowed:
                # Log rate limit violation
                logger.warning(
                    f"Rate limit exceeded for {client_id} on {path}",
                    extra={
                        "client_id": client_id,
                        "path": path,
                        "limit": rate_config["limit"],
                        "window": rate_config["window"],
                        "retry_after": info["retry_after"]
                    }
                )
                
                # Create HTTP response
                response = {
                    "type": "http.response.start",
                    "status": 429,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"x-ratelimit-limit", str(rate_config["limit"]).encode()),
                        (b"x-ratelimit-remaining", str(info["remaining"]).encode()),
                        (b"x-ratelimit-reset", str(int(info["reset_time"])).encode()),
                        (b"retry-after", str(info["retry_after"]).encode()),
                    ],
                }
                
                await send(response)
                
                response_body = {
                    "type": "http.response.body",
                    "body": json.dumps({
                        "error": "Rate limit exceeded",
                        "retry_after": info["retry_after"],
                        "limit": rate_config["limit"],
                        "window": rate_config["window"]
                    }).encode(),
                }
                
                await send(response_body)
                return
            
            # Add rate limit headers to successful responses
            async def send_wrapper(message):
                if message["type"] == "http.response.start":
                    headers = list(message.get("headers", []))
                    headers.extend([
                        (b"x-ratelimit-limit", str(rate_config["limit"]).encode()),
                        (b"x-ratelimit-remaining", str(info["remaining"]).encode()),
                        (b"x-ratelimit-reset", str(int(info["reset_time"])).encode()),
                    ])
                    message["headers"] = headers
                await send(message)
            
            await self.app(scope, receive, send_wrapper)
        else:
            await self.app(scope, receive, send)
    
    def _get_rate_config(self, path: str) -> Dict[str, int]:
        """Get rate limit configuration for a path."""
        # Exact match first
        if path in self.rate_limits:
            return self.rate_limits[path]
        
        # Prefix match
        for pattern, config in self.rate_limits.items():
            if pattern != "default" and path.startswith(pattern):
                return config
        
        # Default configuration
        return self.rate_limits["default"]
    
    def _get_client_id(self, request: Request) -> str:
        """Get client identifier for rate limiting."""
        # Try to get user ID from authenticated request
        if hasattr(request.state, 'user') and request.state.user:
            return f"user:{request.state.user.id}"
        
        # Fall back to IP address
        return f"ip:{get_remote_address(request)}"


def create_rate_limiter(redis_url: str = None):
    """Create rate limiter instance."""
    return RateLimitMiddleware, redis_url


# Import json for response body
import json
