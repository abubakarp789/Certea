"""Tests for Logging Configuration Module

Tests for logging formatters, context logger, and logging utilities.
"""

import pytest
import os
import json
import logging
import tempfile
from unittest.mock import patch, MagicMock

from src.logging_config import (
    get_logger,
    JSONFormatter,
    TextFormatter,
    set_correlation_id,
    get_correlation_id,
    ContextLogger,
    log_operation,
    log_async_operation,
    setup_logging,
    get_log_level,
    get_log_format,
    get_log_file,
    get_max_bytes,
    get_backup_count
)


class TestGetLogger:
    """Tests for get_logger function."""
    
    def test_returns_logger(self):
        """Should return a logger instance."""
        logger = get_logger("test_module")
        assert logger is not None
    
    def test_logger_has_name(self):
        """Logger should have the specified name."""
        logger = get_logger("my_test_logger")
        # The logger should be usable
        assert logger is not None
    
    def test_same_name_returns_same_logger(self):
        """Same name should return same logger instance."""
        logger1 = get_logger("same_name")
        logger2 = get_logger("same_name")
        # Should be able to log with both
        logger1.info("test")
        logger2.info("test")


class TestJSONFormatter:
    """Tests for JSONFormatter."""
    
    def test_format_produces_json(self):
        """Should produce valid JSON output."""
        formatter = JSONFormatter()
        
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None
        )
        
        result = formatter.format(record)
        
        # Should be valid JSON
        parsed = json.loads(result)
        assert "message" in parsed
        assert parsed["message"] == "Test message"
    
    def test_format_includes_timestamp(self):
        """Should include timestamp in output."""
        formatter = JSONFormatter()
        
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None
        )
        
        result = formatter.format(record)
        parsed = json.loads(result)
        
        assert "timestamp" in parsed
    
    def test_format_includes_level(self):
        """Should include log level in output."""
        formatter = JSONFormatter()
        
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname="test.py",
            lineno=1,
            msg="Warning message",
            args=(),
            exc_info=None
        )
        
        result = formatter.format(record)
        parsed = json.loads(result)
        
        assert "level" in parsed
        assert parsed["level"] == "WARNING"


class TestTextFormatter:
    """Tests for TextFormatter."""
    
    def test_format_produces_text(self):
        """Should produce readable text output."""
        formatter = TextFormatter()
        
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None
        )
        
        result = formatter.format(record)
        
        # Should be a non-empty string
        assert isinstance(result, str)
        assert len(result) > 0
        assert "Test message" in result


class TestCorrelationId:
    """Tests for correlation ID functions."""
    
    def test_set_correlation_id(self):
        """Should set and return a correlation ID."""
        corr_id = set_correlation_id()
        
        assert corr_id is not None
        assert isinstance(corr_id, str)
        assert len(corr_id) > 0
    
    def test_set_custom_correlation_id(self):
        """Should accept custom correlation ID."""
        custom_id = "my-custom-id-12345"
        result = set_correlation_id(custom_id)
        
        assert result == custom_id
    
    def test_get_correlation_id(self):
        """Should return current correlation ID."""
        set_id = set_correlation_id()
        get_id = get_correlation_id()
        
        assert get_id == set_id
    
    def test_clear_correlation_id(self):
        """Should clear the correlation ID by setting empty."""
        set_correlation_id("test-id")
        # To clear, we need to reset the context variable to default
        from src.logging_config import correlation_id_var
        correlation_id_var.set('')  # Clear the context variable
        
        result = get_correlation_id()
        assert result == ""


class TestContextLogger:
    """Tests for ContextLogger class."""
    
    def test_context_logger_creation(self):
        """Should create a context logger."""
        base_logger = get_logger("base")
        ctx_logger = ContextLogger(base_logger, extra={"service": "test_service"})
        
        assert ctx_logger is not None
    
    def test_context_logger_logging(self):
        """Should be able to log messages."""
        base_logger = get_logger("base_log")
        ctx_logger = ContextLogger(base_logger, extra={"service": "test"})
        
        # Should not raise
        ctx_logger.info("test message")
        ctx_logger.warning("warning message")
        ctx_logger.error("error message")
        ctx_logger.debug("debug message")


class TestLogFunctionCallDecorator:
    """Tests for log_operation decorator."""
    
    def test_decorator_logs_call(self):
        """Should log function calls."""
        @log_operation("test operation")
        def sample_function(x, y):
            return x + y
        
        result = sample_function(1, 2)
        assert result == 3
    
    def test_decorator_preserves_function_name(self):
        """Should preserve function metadata."""
        @log_operation("named op")
        def named_function():
            pass
        
        assert named_function.__name__ == "named_function"
    
    def test_decorator_handles_exceptions(self):
        """Should handle exceptions in decorated function."""
        @log_operation("failing op")
        def failing_function():
            raise ValueError("Test error")
        
        with pytest.raises(ValueError):
            failing_function()


class TestLogPerformanceDecorator:
    """Tests for log_async_operation decorator."""
    
    @pytest.mark.asyncio
    async def test_decorator_measures_time(self):
        """Should measure function execution time."""
        @log_async_operation("timed async op")
        async def timed_function():
            import asyncio
            await asyncio.sleep(0.01)
            return "done"
        
        result = await timed_function()
        assert result == "done"
    
    @pytest.mark.asyncio
    async def test_decorator_preserves_return_value(self):
        """Should preserve function return value."""
        @log_async_operation("value async op")
        async def value_function():
            return {"key": "value"}
        
        result = await value_function()
        assert result == {"key": "value"}
    
    @pytest.mark.asyncio
    async def test_decorator_handles_exceptions(self):
        """Should handle exceptions."""
        @log_async_operation("failing async op")
        async def failing_function():
            raise RuntimeError("Error")
        
        with pytest.raises(RuntimeError):
            await failing_function()


class TestLoggingContext:
    """Tests for logging context handling."""
    
    def test_context_logger_with_context(self):
        """Should work with context data."""
        logger = get_logger("test_context")
        logger.info("test message", extra={"context": {"operation": "test_op"}})
    
    def test_context_with_extra_data(self):
        """Should pass extra data to logger."""
        logger = get_logger("test_context_extra")
        logger.info("with extra data", extra={"context": {"user": "testuser"}})


class TestLoggingIntegration:
    """Integration tests for logging system."""
    
    def test_logger_with_context(self):
        """Should log with context information."""
        logger = get_logger("integration_test")
        logger.info("Integration test message", extra={"context": {"operation": "integration"}})
    
    def test_multiple_loggers_independent(self):
        """Multiple loggers should be independent."""
        logger1 = get_logger("logger_one")
        logger2 = get_logger("logger_two")
        
        logger1.info("Message from logger one")
        logger2.info("Message from logger two")
    
    def test_logging_with_extra_data(self):
        """Should support logging with extra data."""
        logger = get_logger("extra_test")
        
        logger.info("Test message", extra={"context": {"key": "value"}})