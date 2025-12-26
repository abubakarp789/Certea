"""
Rate Limiting Module

Provides configurable rate limiting for API endpoints using slowapi.
Supports per-IP and global rate limiting with customizable limits per endpoint.
"""

import os
from typing import Optional, Callable
from functools import wraps

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request, Response
from fastapi.responses import JSONResponse

from src.logging_config import get_logger

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = get_logger(__name__)


def is_rate_limiting_enabled() -> bool:
    """Check if rate limiting is enabled."""
    return os.getenv('RATE_LIMIT_ENABLED', 'true').lower() == 'true'


def get_rate_limit(endpoint_type: str) -> str:
    """Get rate limit for a specific endpoint type from environment."""
    defaults = {
        'key_generate': '5/minute',
        'sign': '20/minute',
        'verify': '50/minute',
        'ca': '5/minute',
        'logs': '30/minute',
        'default': '100/minute'
    }
    
    env_key = f'RATE_LIMIT_{endpoint_type.upper()}'
    return os.getenv(env_key, defaults.get(endpoint_type, defaults['default']))


def custom_key_func(request: Request) -> str:
    """
    Custom key function for rate limiting.
    
    Uses client IP address as the rate limit key.
    Falls back to 'unknown' if IP cannot be determined.
    """
    return get_remote_address(request) or 'unknown'


# Create the limiter instance
limiter = Limiter(
    key_func=custom_key_func,
    default_limits=["100/minute"],
    enabled=is_rate_limiting_enabled()
)


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """
    Custom handler for rate limit exceeded errors.
    
    Returns a structured JSON response with retry information.
    """
    # Parse the limit info
    limit_info = str(exc.detail) if hasattr(exc, 'detail') else "Rate limit exceeded"
    
    # Calculate retry-after from the exception
    retry_after = 60  # Default to 60 seconds
    if hasattr(exc, 'retry_after'):
        retry_after = exc.retry_after
    
    logger.warning("Rate limit exceeded", extra={'context': {
        'client_ip': get_remote_address(request) or 'unknown',
        'path': request.url.path,
        'method': request.method,
        'limit_info': limit_info
    }})
    
    response_data = {
        "error": "rate_limit_exceeded",
        "message": f"Too many requests. Please retry after {retry_after} seconds.",
        "retry_after": retry_after,
        "detail": limit_info
    }
    
    return JSONResponse(
        status_code=429,
        content=response_data,
        headers={
            "Retry-After": str(retry_after),
            "X-RateLimit-Limit": limit_info,
            "X-RateLimit-Remaining": "0"
        }
    )


def add_rate_limit_headers(response: Response, limit: str, remaining: int, reset: int) -> Response:
    """Add rate limit headers to response."""
    response.headers["X-RateLimit-Limit"] = limit
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    response.headers["X-RateLimit-Reset"] = str(reset)
    return response


# Rate limit decorators for different endpoint types
def limit_key_generate(func: Callable) -> Callable:
    """Apply rate limiting for key generation endpoints."""
    limit = get_rate_limit('key_generate')
    return limiter.limit(limit)(func)


def limit_sign(func: Callable) -> Callable:
    """Apply rate limiting for signing endpoints."""
    limit = get_rate_limit('sign')
    return limiter.limit(limit)(func)


def limit_verify(func: Callable) -> Callable:
    """Apply rate limiting for verification endpoints."""
    limit = get_rate_limit('verify')
    return limiter.limit(limit)(func)


def limit_ca(func: Callable) -> Callable:
    """Apply rate limiting for CA endpoints."""
    limit = get_rate_limit('ca')
    return limiter.limit(limit)(func)


def limit_logs(func: Callable) -> Callable:
    """Apply rate limiting for log endpoints."""
    limit = get_rate_limit('logs')
    return limiter.limit(limit)(func)


class RateLimitConfig:
    """
    Rate limit configuration class.
    
    Provides centralized access to rate limit settings.
    """
    
    def __init__(self):
        self.enabled = is_rate_limiting_enabled()
        self.limits = {
            'key_generate': get_rate_limit('key_generate'),
            'sign': get_rate_limit('sign'),
            'verify': get_rate_limit('verify'),
            'ca': get_rate_limit('ca'),
            'logs': get_rate_limit('logs')
        }
    
    def get_limit(self, endpoint_type: str) -> str:
        """Get rate limit for endpoint type."""
        return self.limits.get(endpoint_type, '100/minute')
    
    def to_dict(self) -> dict:
        """Return configuration as dictionary."""
        return {
            'enabled': self.enabled,
            'limits': self.limits
        }


# Create global config instance
rate_limit_config = RateLimitConfig()
