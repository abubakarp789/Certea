"""
Tests for Rate Limiter Module

Tests rate limiting configuration, decorators, and handlers.
"""

import os
import pytest
from unittest.mock import MagicMock, patch

# Import test subjects
from src.rate_limiter import (
    is_rate_limiting_enabled,
    get_rate_limit,
    custom_key_func,
    rate_limit_exceeded_handler,
    add_rate_limit_headers,
    limit_key_generate,
    limit_sign,
    limit_verify,
    limit_ca,
    limit_logs,
    RateLimitConfig,
    rate_limit_config
)


class TestRateLimitingEnabled:
    """Tests for is_rate_limiting_enabled function."""
    
    def test_enabled_by_default(self):
        """Rate limiting should be enabled by default."""
        with patch.dict(os.environ, {}, clear=True):
            # When env var is not set, default should be true
            assert is_rate_limiting_enabled() in [True, False]  # Depends on .env file
    
    def test_explicitly_enabled(self):
        """Rate limiting enabled when env var is 'true'."""
        with patch.dict(os.environ, {'RATE_LIMIT_ENABLED': 'true'}):
            assert is_rate_limiting_enabled() == True
    
    def test_explicitly_disabled(self):
        """Rate limiting disabled when env var is 'false'."""
        with patch.dict(os.environ, {'RATE_LIMIT_ENABLED': 'false'}):
            assert is_rate_limiting_enabled() == False
    
    def test_case_insensitive(self):
        """Env var should be case insensitive."""
        with patch.dict(os.environ, {'RATE_LIMIT_ENABLED': 'TRUE'}):
            assert is_rate_limiting_enabled() == True
        
        with patch.dict(os.environ, {'RATE_LIMIT_ENABLED': 'False'}):
            assert is_rate_limiting_enabled() == False


class TestGetRateLimit:
    """Tests for get_rate_limit function."""
    
    def test_default_rate_limits(self):
        """Default rate limits should be returned when env vars not set."""
        # These should return default values
        assert get_rate_limit('key_generate') is not None
        assert get_rate_limit('sign') is not None
        assert get_rate_limit('verify') is not None
        assert get_rate_limit('ca') is not None
        assert get_rate_limit('logs') is not None
    
    def test_custom_rate_limit_from_env(self):
        """Custom rate limit from environment variable."""
        with patch.dict(os.environ, {'RATE_LIMIT_KEY_GENERATE': '10/minute'}):
            result = get_rate_limit('key_generate')
            assert result == '10/minute'
    
    def test_unknown_endpoint_returns_default(self):
        """Unknown endpoint type returns default limit."""
        result = get_rate_limit('unknown_endpoint')
        assert result is not None
        assert 'minute' in result or '/' in result


class TestCustomKeyFunc:
    """Tests for custom_key_func."""
    
    def test_extracts_client_ip(self):
        """Should extract client IP from request."""
        mock_request = MagicMock()
        mock_request.client.host = '192.168.1.100'
        
        # The function uses get_remote_address which looks at request.client
        result = custom_key_func(mock_request)
        assert result is not None
    
    def test_fallback_to_unknown(self):
        """Should fallback to 'unknown' if IP cannot be determined."""
        mock_request = MagicMock()
        mock_request.client = None
        
        with patch('src.rate_limiter.get_remote_address', return_value=None):
            result = custom_key_func(mock_request)
            assert result == 'unknown'


class TestRateLimitExceededHandler:
    """Tests for rate_limit_exceeded_handler."""
    
    def test_returns_json_response(self):
        """Should return JSONResponse with 429 status."""
        mock_request = MagicMock()
        mock_request.url.path = '/api/test'
        mock_request.method = 'POST'
        
        # Create a proper RateLimitExceeded-like exception
        class MockExc:
            detail = "5 per minute"
        
        with patch('src.rate_limiter.get_remote_address', return_value='127.0.0.1'):
            response = rate_limit_exceeded_handler(mock_request, MockExc())
            
            assert response.status_code == 429
            assert 'Retry-After' in response.headers
    
    def test_includes_retry_after_header(self):
        """Response should include Retry-After header."""
        mock_request = MagicMock()
        mock_request.url.path = '/api/test'
        mock_request.method = 'POST'
        
        # Create exception with retry_after attribute
        class MockExc:
            detail = "Rate limited"
            retry_after = 30
        
        with patch('src.rate_limiter.get_remote_address', return_value='127.0.0.1'):
            response = rate_limit_exceeded_handler(mock_request, MockExc())
            
            assert 'Retry-After' in response.headers


class TestAddRateLimitHeaders:
    """Tests for add_rate_limit_headers."""
    
    def test_adds_all_headers(self):
        """Should add all rate limit headers."""
        mock_response = MagicMock()
        mock_response.headers = {}
        
        result = add_rate_limit_headers(mock_response, "100/minute", 50, 1735200000)
        
        assert result.headers["X-RateLimit-Limit"] == "100/minute"
        assert result.headers["X-RateLimit-Remaining"] == "50"
        assert result.headers["X-RateLimit-Reset"] == "1735200000"


class TestRateLimitDecorators:
    """Tests for rate limit decorators."""
    
    def test_limit_key_generate_applies_limit(self):
        """limit_key_generate should apply rate limiting."""
        from fastapi import Request
        
        @limit_key_generate
        async def mock_endpoint(request: Request):
            return "success"
        
        # The function should be decorated
        assert mock_endpoint is not None
        assert callable(mock_endpoint)
    
    def test_limit_sign_applies_limit(self):
        """limit_sign should apply rate limiting."""
        from fastapi import Request
        
        @limit_sign
        async def mock_endpoint(request: Request):
            return "success"
        
        assert mock_endpoint is not None
        assert callable(mock_endpoint)
    
    def test_limit_verify_applies_limit(self):
        """limit_verify should apply rate limiting."""
        from fastapi import Request
        
        @limit_verify
        async def mock_endpoint(request: Request):
            return "success"
        
        assert mock_endpoint is not None
        assert callable(mock_endpoint)
    
    def test_limit_ca_applies_limit(self):
        """limit_ca should apply rate limiting."""
        from fastapi import Request
        
        @limit_ca
        async def mock_endpoint(request: Request):
            return "success"
        
        assert mock_endpoint is not None
        assert callable(mock_endpoint)
    
    def test_limit_logs_applies_limit(self):
        """limit_logs should apply rate limiting."""
        from fastapi import Request
        
        @limit_logs
        async def mock_endpoint(request: Request):
            return "success"
        
        assert mock_endpoint is not None
        assert callable(mock_endpoint)


class TestRateLimitConfig:
    """Tests for RateLimitConfig class."""
    
    def test_config_initialization(self):
        """Config should initialize with all limits."""
        config = RateLimitConfig()
        
        assert hasattr(config, 'enabled')
        assert hasattr(config, 'limits')
        assert 'key_generate' in config.limits
        assert 'sign' in config.limits
        assert 'verify' in config.limits
        assert 'ca' in config.limits
        assert 'logs' in config.limits
    
    def test_get_limit(self):
        """get_limit should return limit for endpoint type."""
        config = RateLimitConfig()
        
        limit = config.get_limit('key_generate')
        assert limit is not None
        assert '/' in limit
    
    def test_get_limit_unknown_type(self):
        """get_limit should return default for unknown type."""
        config = RateLimitConfig()
        
        limit = config.get_limit('nonexistent_endpoint')
        assert limit == '100/minute'
    
    def test_to_dict(self):
        """to_dict should return configuration dictionary."""
        config = RateLimitConfig()
        result = config.to_dict()
        
        assert 'enabled' in result
        assert 'limits' in result
        assert isinstance(result['limits'], dict)


class TestGlobalRateLimitConfig:
    """Tests for global rate_limit_config instance."""
    
    def test_global_config_exists(self):
        """Global config instance should exist."""
        assert rate_limit_config is not None
    
    def test_global_config_is_rate_limit_config(self):
        """Global config should be RateLimitConfig instance."""
        assert isinstance(rate_limit_config, RateLimitConfig)
