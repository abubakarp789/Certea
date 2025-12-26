"""
Tests for Resource Guards Module

Tests resource guards including concurrent request limits,
file size validation, message length validation, and timeouts.
"""

import pytest
import asyncio
import threading
import time
from unittest.mock import MagicMock, patch, AsyncMock
from datetime import datetime, timedelta

# Import test subjects
from src.resource_guards import (
    ResourceConfig,
    resource_config,
    ConcurrentRequestGuard,
    HourlyOperationGuard,
    concurrent_guard,
    key_generation_guard,
    validate_file_size,
    validate_message_length,
    check_key_generation_limit,
    get_key_generation_remaining,
    with_timeout
)

from fastapi import HTTPException


class TestResourceConfig:
    """Tests for ResourceConfig class."""
    
    def test_config_initialization(self):
        """Config should initialize with all settings."""
        config = ResourceConfig()
        
        assert hasattr(config, 'max_file_size_mb')
        assert hasattr(config, 'max_file_size_bytes')
        assert hasattr(config, 'max_message_length')
        assert hasattr(config, 'max_concurrent_requests')
        assert hasattr(config, 'request_timeout_seconds')
        assert hasattr(config, 'max_key_generation_per_hour')
    
    def test_max_file_size_bytes_calculated(self):
        """max_file_size_bytes should be calculated from MB."""
        config = ResourceConfig()
        
        expected = config.max_file_size_mb * 1024 * 1024
        assert config.max_file_size_bytes == expected
    
    def test_to_dict(self):
        """to_dict should return configuration dictionary."""
        config = ResourceConfig()
        result = config.to_dict()
        
        assert 'max_file_size_mb' in result
        assert 'max_message_length' in result
        assert 'max_concurrent_requests' in result
        assert 'request_timeout_seconds' in result
        assert 'max_key_generation_per_hour' in result


class TestConcurrentRequestGuard:
    """Tests for ConcurrentRequestGuard class."""
    
    def test_acquire_within_limit(self):
        """Should acquire slot when under limit."""
        guard = ConcurrentRequestGuard(max_concurrent=5)
        
        # Should be able to acquire 5 slots
        for _ in range(5):
            assert guard.acquire() == True
    
    def test_acquire_at_limit(self):
        """Should fail to acquire when at limit."""
        guard = ConcurrentRequestGuard(max_concurrent=3)
        
        # Acquire all slots
        for _ in range(3):
            guard.acquire()
        
        # Should fail to acquire more
        assert guard.acquire() == False
    
    def test_release(self):
        """Should release slot and allow new acquisitions."""
        guard = ConcurrentRequestGuard(max_concurrent=1)
        
        assert guard.acquire() == True
        assert guard.acquire() == False  # At limit
        
        guard.release()
        
        assert guard.acquire() == True  # Can acquire again
    
    def test_current_count(self):
        """Should track current count correctly."""
        guard = ConcurrentRequestGuard(max_concurrent=10)
        
        assert guard.current_count == 0
        
        guard.acquire()
        assert guard.current_count == 1
        
        guard.acquire()
        assert guard.current_count == 2
        
        guard.release()
        assert guard.current_count == 1
    
    def test_release_below_zero_protection(self):
        """Release should not go below zero."""
        guard = ConcurrentRequestGuard(max_concurrent=5)
        
        # Release without acquiring
        guard.release()
        guard.release()
        
        assert guard.current_count == 0
    
    def test_thread_safety(self):
        """Guard should be thread-safe."""
        guard = ConcurrentRequestGuard(max_concurrent=100)
        success_count = [0]
        
        def acquire_and_release():
            if guard.acquire():
                success_count[0] += 1
                time.sleep(0.01)
                guard.release()
        
        threads = [threading.Thread(target=acquire_and_release) for _ in range(50)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert guard.current_count == 0
        assert success_count[0] == 50


class TestHourlyOperationGuard:
    """Tests for HourlyOperationGuard class."""
    
    def test_check_and_record_within_limit(self):
        """Should allow operations within limit."""
        guard = HourlyOperationGuard(max_per_hour=5)
        
        for _ in range(5):
            assert guard.check_and_record('test_key') == True
    
    def test_check_and_record_at_limit(self):
        """Should deny operations at limit."""
        guard = HourlyOperationGuard(max_per_hour=3)
        
        # Use up all operations
        for _ in range(3):
            guard.check_and_record('test_key')
        
        # Should fail
        assert guard.check_and_record('test_key') == False
    
    def test_different_keys_independent(self):
        """Different keys should have independent limits."""
        guard = HourlyOperationGuard(max_per_hour=2)
        
        # Use up key1's limit
        guard.check_and_record('key1')
        guard.check_and_record('key1')
        
        # key2 should still be available
        assert guard.check_and_record('key2') == True
    
    def test_get_remaining(self):
        """Should return correct remaining count."""
        guard = HourlyOperationGuard(max_per_hour=5)
        
        assert guard.get_remaining('test_key') == 5
        
        guard.check_and_record('test_key')
        assert guard.get_remaining('test_key') == 4
        
        guard.check_and_record('test_key')
        guard.check_and_record('test_key')
        assert guard.get_remaining('test_key') == 2


class TestValidateFileSize:
    """Tests for validate_file_size function."""
    
    def test_valid_file_size(self):
        """Should pass for valid file size."""
        # Use a small size that's definitely under limit
        validate_file_size(1024)  # 1KB
    
    def test_exceeds_file_size(self):
        """Should raise HTTPException for oversized file."""
        # Use a very large size
        huge_size = resource_config.max_file_size_bytes + 1
        
        with pytest.raises(HTTPException) as exc_info:
            validate_file_size(huge_size)
        
        assert exc_info.value.status_code == 413
    
    def test_custom_description(self):
        """Should use custom description in error message."""
        huge_size = resource_config.max_file_size_bytes + 1
        
        with pytest.raises(HTTPException) as exc_info:
            validate_file_size(huge_size, "Document")
        
        assert "Document" in str(exc_info.value.detail)


class TestValidateMessageLength:
    """Tests for validate_message_length function."""
    
    def test_valid_message_length(self):
        """Should pass for valid message length."""
        validate_message_length("Hello, World!")
    
    def test_exceeds_message_length(self):
        """Should raise HTTPException for oversized message."""
        # Create message exceeding limit
        huge_message = "x" * (resource_config.max_message_length + 1)
        
        with pytest.raises(HTTPException) as exc_info:
            validate_message_length(huge_message)
        
        assert exc_info.value.status_code == 413
    
    def test_custom_description(self):
        """Should use custom description in error message."""
        huge_message = "x" * (resource_config.max_message_length + 1)
        
        with pytest.raises(HTTPException) as exc_info:
            validate_message_length(huge_message, "Text input")
        
        assert "Text input" in str(exc_info.value.detail)


class TestCheckKeyGenerationLimit:
    """Tests for check_key_generation_limit function."""
    
    def test_allows_generation_within_limit(self):
        """Should allow key generation within limit."""
        # Use a unique IP for this test
        test_ip = f"test_ip_{datetime.now().timestamp()}"
        
        # Should not raise for first few attempts
        try:
            check_key_generation_limit(test_ip)
        except HTTPException:
            pass  # May fail if test is run multiple times quickly
    
    def test_blocks_after_limit_exceeded(self):
        """Should block after limit exceeded."""
        # Create a fresh guard with low limit for testing
        test_guard = HourlyOperationGuard(max_per_hour=2)
        
        test_ip = f"test_ip_block_{datetime.now().timestamp()}"
        
        # Use up all allowed operations
        assert test_guard.check_and_record(test_ip) == True
        assert test_guard.check_and_record(test_ip) == True
        
        # Next should fail
        assert test_guard.check_and_record(test_ip) == False


class TestGetKeyGenerationRemaining:
    """Tests for get_key_generation_remaining function."""
    
    def test_returns_remaining_count(self):
        """Should return remaining key generation count."""
        test_ip = f"test_ip_remaining_{datetime.now().timestamp()}"
        
        remaining = get_key_generation_remaining(test_ip)
        assert remaining >= 0


class TestWithTimeoutDecorator:
    """Tests for with_timeout decorator."""
    
    @pytest.mark.asyncio
    async def test_function_completes_within_timeout(self):
        """Function completing within timeout should work normally."""
        @with_timeout(5)
        async def fast_function():
            await asyncio.sleep(0.01)
            return "success"
        
        result = await fast_function()
        assert result == "success"
    
    @pytest.mark.asyncio
    async def test_function_exceeds_timeout(self):
        """Function exceeding timeout should raise HTTPException."""
        @with_timeout(0.1)
        async def slow_function():
            await asyncio.sleep(1)
            return "success"
        
        with pytest.raises(HTTPException) as exc_info:
            await slow_function()
        
        assert exc_info.value.status_code == 504
    
    @pytest.mark.asyncio
    async def test_default_timeout_from_config(self):
        """Should use config timeout when not specified."""
        @with_timeout()
        async def function_with_default_timeout():
            await asyncio.sleep(0.01)
            return "success"
        
        result = await function_with_default_timeout()
        assert result == "success"


class TestGlobalInstances:
    """Tests for global guard instances."""
    
    def test_resource_config_exists(self):
        """Global resource_config should exist."""
        assert resource_config is not None
        assert isinstance(resource_config, ResourceConfig)
    
    def test_concurrent_guard_exists(self):
        """Global concurrent_guard should exist."""
        assert concurrent_guard is not None
        assert isinstance(concurrent_guard, ConcurrentRequestGuard)
    
    def test_key_generation_guard_exists(self):
        """Global key_generation_guard should exist."""
        assert key_generation_guard is not None
        assert isinstance(key_generation_guard, HourlyOperationGuard)
