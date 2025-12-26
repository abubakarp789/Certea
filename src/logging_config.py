"""
Centralized Logging Configuration

Provides structured logging with JSON and text formatters, log rotation,
and environment-based configuration for the Digital Signature Validator.
"""

import os
import sys
import json
import logging
import uuid
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Optional, Dict, Any
from functools import wraps
import time
from contextvars import ContextVar

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Context variable for correlation ID (request tracing)
correlation_id_var: ContextVar[str] = ContextVar('correlation_id', default='')


def get_correlation_id() -> str:
    """Get the current correlation ID for request tracing."""
    return correlation_id_var.get()


def set_correlation_id(correlation_id: Optional[str] = None) -> str:
    """Set a new correlation ID for request tracing."""
    new_id = correlation_id or str(uuid.uuid4())[:8]
    correlation_id_var.set(new_id)
    return new_id


class JSONFormatter(logging.Formatter):
    """
    Custom JSON formatter for structured logging.
    
    Produces log entries in JSON format suitable for log aggregation
    and analysis tools like ELK stack or CloudWatch.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add correlation ID if available
        corr_id = get_correlation_id()
        if corr_id:
            log_entry["correlation_id"] = corr_id
        
        # Add extra context if provided
        if hasattr(record, 'context') and record.context:
            log_entry["context"] = record.context
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry, default=str)


class TextFormatter(logging.Formatter):
    """
    Custom text formatter with colored output for development.
    """
    
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as colored text."""
        # Get correlation ID
        corr_id = get_correlation_id()
        corr_str = f"[{corr_id}] " if corr_id else ""
        
        # Apply color if terminal supports it
        color = self.COLORS.get(record.levelname, '')
        reset = self.RESET if color else ''
        
        # Build message
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        base_msg = f"{timestamp} | {color}{record.levelname:8}{reset} | {record.name} | {corr_str}{record.getMessage()}"
        
        # Add context if available
        if hasattr(record, 'context') and record.context:
            context_str = ' | '.join(f"{k}={v}" for k, v in record.context.items())
            base_msg += f" | {context_str}"
        
        # Add exception if present
        if record.exc_info:
            base_msg += f"\n{self.formatException(record.exc_info)}"
        
        return base_msg


class ContextLogger(logging.LoggerAdapter):
    """
    Logger adapter that adds context to log messages.
    
    Allows adding structured context data to log entries.
    """
    
    def process(self, msg: str, kwargs: Dict[str, Any]) -> tuple:
        """Process log message with extra context."""
        extra = kwargs.get('extra', {})
        
        # Merge context from adapter and call
        context = {}
        if self.extra:
            context.update(self.extra)
        if 'context' in extra:
            context.update(extra['context'])
        
        if context:
            extra['context'] = context
            kwargs['extra'] = extra
        
        return msg, kwargs


def get_log_level() -> int:
    """Get log level from environment."""
    level_name = os.getenv('LOG_LEVEL', 'INFO').upper()
    return getattr(logging, level_name, logging.INFO)


def get_log_format() -> str:
    """Get log format from environment (json or text)."""
    return os.getenv('LOG_FORMAT', 'json').lower()


def get_log_file() -> str:
    """Get log file path from environment."""
    return os.getenv('LOG_FILE', 'logs/app.log')


def get_max_bytes() -> int:
    """Get max log file size in bytes."""
    mb = int(os.getenv('LOG_MAX_SIZE_MB', '10'))
    return mb * 1024 * 1024


def get_backup_count() -> int:
    """Get number of backup log files."""
    return int(os.getenv('LOG_BACKUP_COUNT', '5'))


def setup_logging(
    name: Optional[str] = None,
    level: Optional[int] = None,
    log_format: Optional[str] = None,
    log_file: Optional[str] = None
) -> logging.Logger:
    """
    Set up and configure a logger instance.
    
    Args:
        name: Logger name (defaults to root)
        level: Log level (defaults to env LOG_LEVEL)
        log_format: 'json' or 'text' (defaults to env LOG_FORMAT)
        log_file: Path to log file (defaults to env LOG_FILE)
        
    Returns:
        Configured logger instance
    """
    # Get configuration
    level = level or get_log_level()
    log_format = log_format or get_log_format()
    log_file = log_file or get_log_file()
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Select formatter
    if log_format == 'json':
        formatter = JSONFormatter()
    else:
        formatter = TextFormatter()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)
    logger.addHandler(console_handler)
    
    # File handler with rotation
    try:
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=get_max_bytes(),
            backupCount=get_backup_count()
        )
        # Always use JSON for file logging for easier parsing
        file_handler.setFormatter(JSONFormatter())
        file_handler.setLevel(level)
        logger.addHandler(file_handler)
    except Exception as e:
        logger.warning(f"Could not set up file logging: {e}")
    
    return logger


def get_logger(name: str, context: Optional[Dict[str, Any]] = None) -> ContextLogger:
    """
    Get a logger with optional context.
    
    Args:
        name: Logger name (typically __name__)
        context: Optional context dictionary to include in all logs
        
    Returns:
        ContextLogger instance
    """
    logger = logging.getLogger(name)
    
    # Set up if not already configured
    if not logger.handlers:
        setup_logging(name)
    
    return ContextLogger(logger, context or {})


def log_operation(operation: str, logger_name: Optional[str] = None):
    """
    Decorator to log function entry, exit, and timing.
    
    Args:
        operation: Description of the operation
        logger_name: Optional logger name (defaults to function's module)
        
    Returns:
        Decorated function
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            log_name = logger_name or func.__module__
            log = get_logger(log_name)
            
            start_time = time.time()
            
            log.info(f"{operation} started", extra={'context': {
                'operation': operation,
                'function': func.__name__
            }})
            
            try:
                result = func(*args, **kwargs)
                
                duration_ms = (time.time() - start_time) * 1000
                log.info(f"{operation} completed", extra={'context': {
                    'operation': operation,
                    'function': func.__name__,
                    'duration_ms': round(duration_ms, 2)
                }})
                
                return result
                
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                log.error(f"{operation} failed: {str(e)}", extra={'context': {
                    'operation': operation,
                    'function': func.__name__,
                    'duration_ms': round(duration_ms, 2),
                    'error': str(e)
                }}, exc_info=True)
                raise
        
        return wrapper
    return decorator


def log_async_operation(operation: str, logger_name: Optional[str] = None):
    """
    Async decorator to log function entry, exit, and timing.
    
    Args:
        operation: Description of the operation
        logger_name: Optional logger name
        
    Returns:
        Decorated async function
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            log_name = logger_name or func.__module__
            log = get_logger(log_name)
            
            start_time = time.time()
            
            log.info(f"{operation} started", extra={'context': {
                'operation': operation,
                'function': func.__name__
            }})
            
            try:
                result = await func(*args, **kwargs)
                
                duration_ms = (time.time() - start_time) * 1000
                log.info(f"{operation} completed", extra={'context': {
                    'operation': operation,
                    'function': func.__name__,
                    'duration_ms': round(duration_ms, 2)
                }})
                
                return result
                
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                log.error(f"{operation} failed: {str(e)}", extra={'context': {
                    'operation': operation,
                    'function': func.__name__,
                    'duration_ms': round(duration_ms, 2),
                    'error': str(e)
                }}, exc_info=True)
                raise
        
        return wrapper
    return decorator


# Initialize root logger on module import
_root_logger = setup_logging()
