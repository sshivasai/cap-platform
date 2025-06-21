"""
Logging configuration and utilities for CAP Platform.

This module provides:
- Structured logging with JSON formatting
- Multiple log handlers (file, console, remote)
- Log rotation and archival
- Security-aware logging (sensitive data masking)
- Performance logging and metrics
- Correlation IDs for request tracking

Designed for production monitoring with proper log levels,
structured output, and integration with log aggregation systems.
"""

import os
import sys
import json
import logging
import logging.handlers
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union
from pathlib import Path
import traceback
import threading
from contextlib import contextmanager

from app.core.config import settings


# ================================
# Log Formatter Classes
# ================================

class JSONFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.
    
    Formats log records as JSON for better parsing by log aggregation systems.
    """
    
    def __init__(self, include_fields: Optional[list] = None):
        super().__init__()
        self.include_fields = include_fields or [
            'timestamp', 'level', 'logger', 'message', 'module', 
            'function', 'line', 'thread', 'process'
        ]
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry = {}
        
        # Basic fields
        if 'timestamp' in self.include_fields:
            log_entry['timestamp'] = datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat()
        
        if 'level' in self.include_fields:
            log_entry['level'] = record.levelname
        
        if 'logger' in self.include_fields:
            log_entry['logger'] = record.name
        
        if 'message' in self.include_fields:
            log_entry['message'] = record.getMessage()
        
        if 'module' in self.include_fields:
            log_entry['module'] = record.module
        
        if 'function' in self.include_fields:
            log_entry['function'] = record.funcName
        
        if 'line' in self.include_fields:
            log_entry['line'] = record.lineno
        
        if 'thread' in self.include_fields:
            log_entry['thread'] = record.thread
        
        if 'process' in self.include_fields:
            log_entry['process'] = record.process
        
        # Add exception information if present
        if record.exc_info:
            log_entry['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': traceback.format_exception(*record.exc_info)
            }
        
        # Add extra fields from log record
        extra_fields = {}
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                          'filename', 'module', 'lineno', 'funcName', 'created',
                          'msecs', 'relativeCreated', 'thread', 'threadName',
                          'processName', 'process', 'getMessage', 'exc_info',
                          'exc_text', 'stack_info']:
                extra_fields[key] = value
        
        if extra_fields:
            log_entry['extra'] = extra_fields
        
        # Add correlation ID if present
        correlation_id = getattr(threading.current_thread(), 'correlation_id', None)
        if correlation_id:
            log_entry['correlation_id'] = correlation_id
        
        return json.dumps(log_entry, default=str, ensure_ascii=False)


class SecurityAwareFormatter(logging.Formatter):
    """
    Formatter that masks sensitive information in log messages.
    """
    
    def __init__(self, fmt=None, datefmt=None):
        super().__init__(fmt, datefmt)
        self.sensitive_patterns = [
            r'password["\']?\s*[:=]\s*["\']?([^"\',\s]+)',
            r'token["\']?\s*[:=]\s*["\']?([^"\',\s]+)',
            r'api[_-]?key["\']?\s*[:=]\s*["\']?([^"\',\s]+)',
            r'secret["\']?\s*[:=]\s*["\']?([^"\',\s]+)',
            r'authorization["\']?\s*[:=]\s*["\']?([^"\',\s]+)',
        ]
    
    def format(self, record: logging.LogRecord) -> str:
        """Format record with sensitive data masking."""
        # Get the formatted message
        msg = super().format(record)
        
        # Mask sensitive information
        import re
        for pattern in self.sensitive_patterns:
            msg = re.sub(pattern, lambda m: m.group(0).replace(m.group(1), '*' * 8), msg, flags=re.IGNORECASE)
        
        return msg


# ================================
# Custom Log Handlers
# ================================

class CorrelationHandler(logging.Handler):
    """
    Handler that adds correlation IDs to log records.
    """
    
    def __init__(self, handler: logging.Handler):
        super().__init__()
        self.handler = handler
        self.setLevel(handler.level)
        self.setFormatter(handler.formatter)
    
    def emit(self, record: logging.LogRecord):
        """Emit log record with correlation ID."""
        # Add correlation ID if available
        correlation_id = getattr(threading.current_thread(), 'correlation_id', None)
        if correlation_id:
            record.correlation_id = correlation_id
        
        self.handler.emit(record)


class AsyncFileHandler(logging.Handler):
    """
    Asynchronous file handler for high-performance logging.
    """
    
    def __init__(self, filename: str, mode: str = 'a', encoding: str = 'utf-8'):
        super().__init__()
        self.filename = filename
        self.mode = mode
        self.encoding = encoding
        self._queue = []
        self._lock = threading.Lock()
        
        # Ensure log directory exists
        Path(filename).parent.mkdir(parents=True, exist_ok=True)
    
    def emit(self, record: logging.LogRecord):
        """Add record to queue for async processing."""
        try:
            msg = self.format(record)
            with self._lock:
                self._queue.append(msg)
        except Exception:
            self.handleError(record)
    
    def flush_queue(self):
        """Flush queued log messages to file."""
        if not self._queue:
            return
        
        with self._lock:
            messages = self._queue.copy()
            self._queue.clear()
        
        try:
            with open(self.filename, self.mode, encoding=self.encoding) as f:
                for message in messages:
                    f.write(message + '\n')
                f.flush()
        except Exception as e:
            print(f"Error writing to log file: {e}", file=sys.stderr)


# ================================
# Logger Configuration
# ================================

class LoggerManager:
    """
    Centralized logger configuration and management.
    """
    
    def __init__(self):
        self._loggers: Dict[str, logging.Logger] = {}
        self._handlers: Dict[str, logging.Handler] = {}
        self._configured = False
    
    def configure_logging(self):
        """Configure application logging."""
        if self._configured:
            return
        
        # Set root logger level
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, settings.LOG_LEVEL))
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # Configure console handler
        self._setup_console_handler()
        
        # Configure file handler
        self._setup_file_handler()
        
        # Configure error file handler
        self._setup_error_file_handler()
        
        # Configure external handlers if in production
        if settings.is_production():
            self._setup_external_handlers()
        
        # Configure third-party loggers
        self._configure_third_party_loggers()
        
        self._configured = True
    
    def _setup_console_handler(self):
        """Set up console logging handler."""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
        
        if settings.is_production():
            # Use JSON formatting in production
            formatter = JSONFormatter()
        else:
            # Use human-readable formatting in development
            formatter = SecurityAwareFormatter(
                fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        
        console_handler.setFormatter(formatter)
        
        # Add correlation tracking
        correlation_handler = CorrelationHandler(console_handler)
        
        # Add to root logger
        logging.getLogger().addHandler(correlation_handler)
        self._handlers['console'] = correlation_handler
    
    def _setup_file_handler(self):
        """Set up file logging handler with rotation."""
        log_file = settings.LOG_FILE_PATH
        
        # Ensure log directory exists
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        
        # Use rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            filename=log_file,
            maxBytes=settings.LOG_MAX_SIZE_MB * 1024 * 1024,  # Convert MB to bytes
            backupCount=settings.LOG_BACKUP_COUNT,
            encoding='utf-8'
        )
        
        file_handler.setLevel(logging.DEBUG)
        
        # Use JSON formatting for file logs
        formatter = JSONFormatter()
        file_handler.setFormatter(formatter)
        
        # Add correlation tracking
        correlation_handler = CorrelationHandler(file_handler)
        
        # Add to root logger
        logging.getLogger().addHandler(correlation_handler)
        self._handlers['file'] = correlation_handler
    
    def _setup_error_file_handler(self):
        """Set up separate error file handler."""
        error_log_file = settings.LOG_FILE_PATH.replace('.log', '_error.log')
        
        error_handler = logging.handlers.RotatingFileHandler(
            filename=error_log_file,
            maxBytes=settings.LOG_MAX_SIZE_MB * 1024 * 1024,
            backupCount=settings.LOG_BACKUP_COUNT,
            encoding='utf-8'
        )
        
        error_handler.setLevel(logging.ERROR)
        
        # Use JSON formatting
        formatter = JSONFormatter()
        error_handler.setFormatter(formatter)
        
        # Add correlation tracking
        correlation_handler = CorrelationHandler(error_handler)
        
        # Add to root logger
        logging.getLogger().addHandler(correlation_handler)
        self._handlers['error'] = correlation_handler
    
    def _setup_external_handlers(self):
        """Set up external logging handlers (Sentry, etc.)."""
        # Sentry integration
        if settings.SENTRY_DSN:
            try:
                import sentry_sdk
                from sentry_sdk.integrations.logging import LoggingIntegration
                
                sentry_logging = LoggingIntegration(
                    level=logging.INFO,        # Capture info and above as breadcrumbs
                    event_level=logging.ERROR  # Send errors as events
                )
                
                sentry_sdk.init(
                    dsn=settings.SENTRY_DSN,
                    integrations=[sentry_logging],
                    environment=settings.ENVIRONMENT,
                    traces_sample_rate=0.1 if settings.is_production() else 1.0,
                )
                
            except ImportError:
                logging.warning("Sentry SDK not available, skipping Sentry integration")
    
    def _configure_third_party_loggers(self):
        """Configure logging levels for third-party libraries."""
        # Reduce noise from third-party libraries
        noisy_loggers = [
            'urllib3.connectionpool',
            'asyncio',
            'websockets',
            'httpx',
            'sqlalchemy.engine',
            'celery.task',
            'amqp',
            'kombu'
        ]
        
        for logger_name in noisy_loggers:
            logger = logging.getLogger(logger_name)
            logger.setLevel(logging.WARNING)
        
        # Set specific levels for our integrations
        logging.getLogger('sqlalchemy.engine').setLevel(
            logging.INFO if settings.DEBUG else logging.WARNING
        )
        
        logging.getLogger('celery').setLevel(logging.INFO)
        logging.getLogger('redis').setLevel(logging.WARNING)
    
    def get_logger(self, name: str) -> logging.Logger:
        """
        Get a configured logger instance.
        
        Args:
            name: Logger name (usually module name)
            
        Returns:
            Configured logger instance
        """
        if not self._configured:
            self.configure_logging()
        
        if name not in self._loggers:
            logger = logging.getLogger(name)
            self._loggers[name] = logger
        
        return self._loggers[name]
    
    def flush_all_handlers(self):
        """Flush all log handlers."""
        for handler in self._handlers.values():
            if hasattr(handler, 'flush'):
                handler.flush()
    
    def close_all_handlers(self):
        """Close all log handlers."""
        for handler in self._handlers.values():
            if hasattr(handler, 'close'):
                handler.close()


# ================================
# Convenience Functions
# ================================

# Create a global instance of LoggerManager
_logger_manager = LoggerManager()

def get_logger(name: str) -> logging.Logger:
    """
    Get a configured logger instance.
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Configured logger instance
    """
    return _logger_manager.get_logger(name)


def configure_logging():
    """Configure application logging."""
    _logger_manager.configure_logging()


def flush_logs():
    """Flush all log handlers."""
    _logger_manager.flush_all_handlers()


def close_logs():
    """Close all log handlers."""
    _logger_manager.close_all_handlers()


# ================================
# Correlation ID Management
# ================================

class CorrelationContext:
    """
    Context manager for correlation ID tracking.
    """
    
    def __init__(self, correlation_id: str):
        self.correlation_id = correlation_id
        self.previous_id = None
    
    def __enter__(self):
        """Set correlation ID for current thread."""
        current_thread = threading.current_thread()
        self.previous_id = getattr(current_thread, 'correlation_id', None)
        current_thread.correlation_id = self.correlation_id
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Restore previous correlation ID."""
        current_thread = threading.current_thread()
        if self.previous_id is not None:
            current_thread.correlation_id = self.previous_id
        else:
            if hasattr(current_thread, 'correlation_id'):
                delattr(current_thread, 'correlation_id')


@contextmanager
def correlation_id(correlation_id: str):
    """
    Context manager for setting correlation ID.
    
    Args:
        correlation_id: Correlation ID to set
        
    Usage:
        with correlation_id("req-123"):
            logger.info("This will include correlation ID")
    """
    with CorrelationContext(correlation_id):
        yield


def set_correlation_id(correlation_id: str):
    """
    Set correlation ID for current thread.
    
    Args:
        correlation_id: Correlation ID to set
    """
    threading.current_thread().correlation_id = correlation_id


def get_correlation_id() -> Optional[str]:
    """
    Get correlation ID for current thread.
    
    Returns:
        Current correlation ID or None
    """
    return getattr(threading.current_thread(), 'correlation_id', None)


def generate_correlation_id() -> str:
    """
    Generate a new correlation ID.
    
    Returns:
        New correlation ID string
    """
    import uuid
    return f"req-{uuid.uuid4().hex[:8]}"


# ================================
# Performance Logging
# ================================

class PerformanceLogger:
    """
    Logger for performance metrics and timing.
    """
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def log_execution_time(
        self,
        operation: str,
        execution_time: float,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log execution time for an operation.
        
        Args:
            operation: Operation name
            execution_time: Execution time in seconds
            metadata: Additional metadata
        """
        log_data = {
            "performance_metric": True,
            "operation": operation,
            "execution_time_seconds": execution_time,
            "execution_time_ms": execution_time * 1000,
            "metadata": metadata or {}
        }
        
        # Log as warning if execution time is high
        if execution_time > 5.0:  # 5 seconds threshold
            self.logger.warning(f"Slow operation: {operation}", extra=log_data)
        elif execution_time > 1.0:  # 1 second threshold
            self.logger.info(f"Operation completed: {operation}", extra=log_data)
        else:
            self.logger.debug(f"Operation completed: {operation}", extra=log_data)
    
    def log_database_query(
        self,
        query_type: str,
        execution_time: float,
        rows_affected: Optional[int] = None,
        query: Optional[str] = None
    ):
        """
        Log database query performance.
        
        Args:
            query_type: Type of query (SELECT, INSERT, etc.)
            execution_time: Query execution time
            rows_affected: Number of rows affected
            query: Sanitized query string
        """
        log_data = {
            "performance_metric": True,
            "metric_type": "database_query",
            "query_type": query_type,
            "execution_time_seconds": execution_time,
            "rows_affected": rows_affected,
            "query": query[:200] + "..." if query and len(query) > 200 else query
        }
        
        if execution_time > 2.0:  # 2 seconds threshold for DB queries
            self.logger.warning(f"Slow database query: {query_type}", extra=log_data)
        else:
            self.logger.debug(f"Database query: {query_type}", extra=log_data)
    
    def log_api_request(
        self,
        method: str,
        path: str,
        status_code: int,
        response_time: float,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None
    ):
        """
        Log API request performance.
        
        Args:
            method: HTTP method
            path: Request path
            status_code: HTTP status code
            response_time: Response time in seconds
            user_id: User ID if authenticated
            ip_address: Client IP address
        """
        log_data = {
            "performance_metric": True,
            "metric_type": "api_request",
            "method": method,
            "path": path,
            "status_code": status_code,
            "response_time_seconds": response_time,
            "response_time_ms": response_time * 1000,
            "user_id": user_id,
            "ip_address": ip_address
        }
        
        # Log level based on status code and response time
        if status_code >= 500:
            self.logger.error(f"API error: {method} {path}", extra=log_data)
        elif status_code >= 400:
            self.logger.warning(f"API client error: {method} {path}", extra=log_data)
        elif response_time > 3.0:
            self.logger.warning(f"Slow API request: {method} {path}", extra=log_data)
        else:
            self.logger.info(f"API request: {method} {path}", extra=log_data)


# ================================
# Decorators for Logging
# ================================

def log_execution_time(logger: Optional[logging.Logger] = None, operation: Optional[str] = None):
    """
    Decorator to log function execution time.
    
    Args:
        logger: Logger to use (defaults to function's module logger)
        operation: Operation name (defaults to function name)
        
    Usage:
        @log_execution_time()
        def slow_function():
            pass
    """
    def decorator(func):
        import time
        from functools import wraps
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            func_logger = logger or get_logger(func.__module__)
            op_name = operation or func.__name__
            
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                
                perf_logger = PerformanceLogger(func_logger)
                perf_logger.log_execution_time(op_name, execution_time)
                
                return result
            except Exception as e:
                execution_time = time.time() - start_time
                func_logger.error(
                    f"Function {op_name} failed after {execution_time:.3f}s: {e}",
                    exc_info=True
                )
                raise
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            import asyncio
            start_time = time.time()
            func_logger = logger or get_logger(func.__module__)
            op_name = operation or func.__name__
            
            try:
                result = await func(*args, **kwargs)
                execution_time = time.time() - start_time
                
                perf_logger = PerformanceLogger(func_logger)
                perf_logger.log_execution_time(op_name, execution_time)
                
                return result
            except Exception as e:
                execution_time = time.time() - start_time
                func_logger.error(
                    f"Async function {op_name} failed after {execution_time:.3f}s: {e}",
                    exc_info=True
                )
                raise
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def log_function_call(
    logger: Optional[logging.Logger] = None,
    log_args: bool = True,
    log_result: bool = False,
    level: int = logging.DEBUG
):
    """
    Decorator to log function calls.
    
    Args:
        logger: Logger to use
        log_args: Whether to log function arguments
        log_result: Whether to log function result
        level: Log level to use
        
    Usage:
        @log_function_call(log_args=True, log_result=True)
        def important_function(arg1, arg2):
            return "result"
    """
    def decorator(func):
        from functools import wraps
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            func_logger = logger or get_logger(func.__module__)
            
            log_data = {"function": func.__name__}
            if log_args:
                log_data["args"] = args
                log_data["kwargs"] = kwargs
            
            func_logger.log(level, f"Calling function: {func.__name__}", extra=log_data)
            
            try:
                result = func(*args, **kwargs)
                
                if log_result:
                    result_data = {"function": func.__name__, "result": result}
                    func_logger.log(level, f"Function completed: {func.__name__}", extra=result_data)
                
                return result
            except Exception as e:
                func_logger.error(f"Function {func.__name__} failed: {e}", exc_info=True)
                raise
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            func_logger = logger or get_logger(func.__module__)
            
            log_data = {"function": func.__name__}
            if log_args:
                log_data["args"] = args
                log_data["kwargs"] = kwargs
            
            func_logger.log(level, f"Calling async function: {func.__name__}", extra=log_data)
            
            try:
                result = await func(*args, **kwargs)
                
                if log_result:
                    result_data = {"function": func.__name__, "result": result}
                    func_logger.log(level, f"Async function completed: {func.__name__}", extra=result_data)
                
                return result
            except Exception as e:
                func_logger.error(f"Async function {func.__name__} failed: {e}", exc_info=True)
                raise
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


# ================================
# Context Managers for Logging
# ================================

@contextmanager
def log_operation(
    operation: str,
    logger: Optional[logging.Logger] = None,
    level: int = logging.INFO,
    log_success: bool = True,
    log_failure: bool = True
):
    """
    Context manager for logging operations.
    
    Args:
        operation: Operation name
        logger: Logger to use
        level: Log level for success messages
        log_success: Whether to log successful completion
        log_failure: Whether to log failures
        
    Usage:
        with log_operation("user_registration"):
            # Operation code here
            pass
    """
    import time
    
    op_logger = logger or get_logger(__name__)
    start_time = time.time()
    
    op_logger.log(level, f"Starting operation: {operation}")
    
    try:
        yield
        
        if log_success:
            execution_time = time.time() - start_time
            op_logger.log(
                level,
                f"Operation completed: {operation}",
                extra={
                    "operation": operation,
                    "execution_time_seconds": execution_time,
                    "status": "success"
                }
            )
    
    except Exception as e:
        if log_failure:
            execution_time = time.time() - start_time
            op_logger.error(
                f"Operation failed: {operation}",
                exc_info=True,
                extra={
                    "operation": operation,
                    "execution_time_seconds": execution_time,
                    "status": "failed",
                    "error": str(e)
                }
            )
        raise


# ================================
# Audit Logging
# ================================

class AuditLogger:
    """
    Specialized logger for audit events.
    """
    
    def __init__(self):
        self.logger = get_logger("audit")
    
    def log_user_action(
        self,
        user_id: str,
        action: str,
        resource: str,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Log user actions for audit purposes.
        
        Args:
            user_id: User performing the action
            action: Action being performed
            resource: Resource being acted upon
            resource_id: ID of the specific resource
            ip_address: User's IP address
            user_agent: User's browser/client
            success: Whether the action was successful
            details: Additional action details
        """
        audit_data = {
            "audit_event": True,
            "user_id": user_id,
            "action": action,
            "resource": resource,
            "resource_id": resource_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "success": success,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details or {}
        }
        
        level = logging.INFO if success else logging.WARNING
        self.logger.log(
            level,
            f"User action: {action} on {resource}",
            extra=audit_data
        )
    
    def log_system_event(
        self,
        event_type: str,
        description: str,
        severity: str = "info",
        component: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Log system events for audit purposes.
        
        Args:
            event_type: Type of system event
            description: Event description
            severity: Event severity (info, warning, error, critical)
            component: System component involved
            details: Additional event details
        """
        audit_data = {
            "audit_event": True,
            "event_type": "system",
            "system_event_type": event_type,
            "description": description,
            "severity": severity,
            "component": component,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details or {}
        }
        
        level = getattr(logging, severity.upper(), logging.INFO)
        self.logger.log(
            level,
            f"System event: {event_type}",
            extra=audit_data
        )


# ================================
# Global Instances
# ================================

# Global audit logger
audit_logger = AuditLogger()


# ================================
# Initialization and Cleanup
# ================================

def init_logging():
    """Initialize logging configuration."""
    configure_logging()
    
    # Log startup message
    logger = get_logger(__name__)
    logger.info(
        f"Logging initialized",
        extra={
            "log_level": settings.LOG_LEVEL,
            "log_file": settings.LOG_FILE_PATH,
            "environment": settings.ENVIRONMENT
        }
    )


def cleanup_logging():
    """Cleanup logging resources."""
    logger = get_logger(__name__)
    logger.info("Shutting down logging")
    
    # Flush and close all handlers
    flush_logs()
    close_logs()


# ================================
# Auto-configuration
# ================================

# Configure logging on module import
configure_logging()