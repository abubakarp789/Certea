"""
Resource Guards Module

Provides protection against resource exhaustion through:
- File size limits
- Request timeouts
- Concurrent request limiting
- Input validation guards
"""

import os
import asyncio
from typing import Optional, Callable, Any
from functools import wraps
from datetime import datetime, timedelta
from collections import defaultdict
import threading

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from src.logging_config import get_logger

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = get_logger(__name__)


class ResourceConfig:
    """Resource guard configuration from environment."""
    
    def __init__(self):
        self.max_file_size_mb = int(os.getenv('MAX_FILE_SIZE_MB', '1024'))
        self.max_file_size_bytes = self.max_file_size_mb * 1024 * 1024
        self.max_message_length = int(os.getenv('MAX_MESSAGE_LENGTH', '10485760'))
        self.max_concurrent_requests = int(os.getenv('MAX_CONCURRENT_REQUESTS', '100'))
        self.request_timeout_seconds = int(os.getenv('REQUEST_TIMEOUT_SECONDS', '30'))
        self.max_key_generation_per_hour = int(os.getenv('MAX_KEY_GENERATION_PER_HOUR', '50'))
    
    def to_dict(self) -> dict:
        """Return configuration as dictionary."""
        return {
            'max_file_size_mb': self.max_file_size_mb,
            'max_message_length': self.max_message_length,
            'max_concurrent_requests': self.max_concurrent_requests,
            'request_timeout_seconds': self.request_timeout_seconds,
            'max_key_generation_per_hour': self.max_key_generation_per_hour
        }


# Global configuration instance
resource_config = ResourceConfig()


class ConcurrentRequestGuard:
    """
    Guard against too many concurrent requests.
    
    Thread-safe counter for tracking active requests.
    """
    
    def __init__(self, max_concurrent: int = 100):
        self.max_concurrent = max_concurrent
        self._count = 0
        self._lock = threading.Lock()
    
    def acquire(self) -> bool:
        """Try to acquire a request slot. Returns False if limit reached."""
        with self._lock:
            if self._count >= self.max_concurrent:
                return False
            self._count += 1
            return True
    
    def release(self):
        """Release a request slot."""
        with self._lock:
            self._count = max(0, self._count - 1)
    
    @property
    def current_count(self) -> int:
        """Get current concurrent request count."""
        with self._lock:
            return self._count


class HourlyOperationGuard:
    """
    Guard against too many operations per hour per IP.
    
    Tracks operation counts with automatic cleanup.
    """
    
    def __init__(self, max_per_hour: int = 50):
        self.max_per_hour = max_per_hour
        self._counts: dict = defaultdict(list)
        self._lock = threading.Lock()
    
    def check_and_record(self, key: str) -> bool:
        """
        Check if operation is allowed and record it.
        
        Returns True if allowed, False if limit exceeded.
        """
        now = datetime.now()
        hour_ago = now - timedelta(hours=1)
        
        with self._lock:
            # Clean up old entries
            self._counts[key] = [
                ts for ts in self._counts[key]
                if ts > hour_ago
            ]
            
            # Check limit
            if len(self._counts[key]) >= self.max_per_hour:
                return False
            
            # Record new operation
            self._counts[key].append(now)
            return True
    
    def get_remaining(self, key: str) -> int:
        """Get remaining operations for key in current hour."""
        now = datetime.now()
        hour_ago = now - timedelta(hours=1)
        
        with self._lock:
            current_count = len([
                ts for ts in self._counts[key]
                if ts > hour_ago
            ])
            return max(0, self.max_per_hour - current_count)


# Global guard instances
concurrent_guard = ConcurrentRequestGuard(resource_config.max_concurrent_requests)
key_generation_guard = HourlyOperationGuard(resource_config.max_key_generation_per_hour)


class ResourceGuardMiddleware(BaseHTTPMiddleware):
    """
    Middleware for enforcing resource guards.
    
    Checks:
    - Concurrent request limit
    - Request timeout
    - Content length for uploads
    """
    
    async def dispatch(self, request: Request, call_next):
        """Process request with resource guards."""
        
        # Check concurrent request limit
        if not concurrent_guard.acquire():
            logger.warning("Concurrent request limit exceeded", extra={'context': {
                'path': request.url.path,
                'current_count': concurrent_guard.current_count
            }})
            return JSONResponse(
                status_code=503,
                content={
                    "error": "server_busy",
                    "message": "Server is busy. Please retry later.",
                    "current_load": concurrent_guard.current_count
                }
            )
        
        try:
            # Check content length if present
            content_length = request.headers.get('content-length')
            if content_length:
                try:
                    size = int(content_length)
                    if size > resource_config.max_file_size_bytes:
                        logger.warning("Request too large", extra={'context': {
                            'path': request.url.path,
                            'content_length': size,
                            'max_allowed': resource_config.max_file_size_bytes
                        }})
                        return JSONResponse(
                            status_code=413,
                            content={
                                "error": "request_too_large",
                                "message": f"Request exceeds maximum size of {resource_config.max_file_size_mb}MB",
                                "max_size_mb": resource_config.max_file_size_mb
                            }
                        )
                except ValueError:
                    pass
            
            # Apply timeout
            try:
                response = await asyncio.wait_for(
                    call_next(request),
                    timeout=resource_config.request_timeout_seconds
                )
                return response
            except asyncio.TimeoutError:
                logger.error("Request timeout", extra={'context': {
                    'path': request.url.path,
                    'timeout_seconds': resource_config.request_timeout_seconds
                }})
                return JSONResponse(
                    status_code=504,
                    content={
                        "error": "request_timeout",
                        "message": f"Operation timed out after {resource_config.request_timeout_seconds} seconds",
                        "timeout_seconds": resource_config.request_timeout_seconds
                    }
                )
        finally:
            concurrent_guard.release()


def validate_file_size(size_bytes: int, description: str = "File") -> None:
    """
    Validate file size against maximum limit.
    
    Args:
        size_bytes: File size in bytes
        description: Description for error message
        
    Raises:
        HTTPException: If file size exceeds limit
    """
    if size_bytes > resource_config.max_file_size_bytes:
        logger.warning(f"{description} size exceeds limit", extra={'context': {
            'size_bytes': size_bytes,
            'max_bytes': resource_config.max_file_size_bytes
        }})
        raise HTTPException(
            status_code=413,
            detail=f"{description} exceeds maximum size of {resource_config.max_file_size_mb}MB"
        )


def validate_message_length(message: str, description: str = "Message") -> None:
    """
    Validate message length against maximum limit.
    
    Args:
        message: Message string
        description: Description for error message
        
    Raises:
        HTTPException: If message length exceeds limit
    """
    if len(message) > resource_config.max_message_length:
        logger.warning(f"{description} length exceeds limit", extra={'context': {
            'length': len(message),
            'max_length': resource_config.max_message_length
        }})
        raise HTTPException(
            status_code=413,
            detail=f"{description} exceeds maximum length of {resource_config.max_message_length} characters"
        )


def check_key_generation_limit(client_ip: str) -> None:
    """
    Check if client can generate more keys.
    
    Args:
        client_ip: Client IP address
        
    Raises:
        HTTPException: If hourly limit exceeded
    """
    if not key_generation_guard.check_and_record(client_ip):
        remaining = key_generation_guard.get_remaining(client_ip)
        logger.warning("Key generation limit exceeded", extra={'context': {
            'client_ip': client_ip,
            'max_per_hour': resource_config.max_key_generation_per_hour
        }})
        raise HTTPException(
            status_code=429,
            detail=f"Key generation limit reached. Maximum {resource_config.max_key_generation_per_hour} keys per hour."
        )


def get_key_generation_remaining(client_ip: str) -> int:
    """Get remaining key generations for client in current hour."""
    return key_generation_guard.get_remaining(client_ip)


def with_timeout(timeout_seconds: Optional[int] = None):
    """
    Decorator to add timeout to async functions.
    
    Args:
        timeout_seconds: Timeout in seconds (defaults to config value)
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            timeout = timeout_seconds or resource_config.request_timeout_seconds
            try:
                return await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                logger.error(f"Function {func.__name__} timed out", extra={'context': {
                    'function': func.__name__,
                    'timeout_seconds': timeout
                }})
                raise HTTPException(
                    status_code=504,
                    detail=f"Operation timed out after {timeout} seconds"
                )
        return wrapper
    return decorator
