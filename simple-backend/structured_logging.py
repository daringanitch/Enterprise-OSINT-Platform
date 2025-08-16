#!/usr/bin/env python3
"""
Structured Logging with OpenTelemetry Trace Correlation
Implements enterprise-grade logging for OSINT platform
"""

import os
import sys
import json
import logging
import time
from datetime import datetime
from typing import Dict, Any, Optional
from functools import wraps

try:
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False


class TraceCorrelatedLogger:
    """Logger that automatically includes OpenTelemetry trace correlation"""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.name = name
    
    def _get_trace_context(self) -> Dict[str, str]:
        """Extract current trace context"""
        context = {}
        
        if OTEL_AVAILABLE:
            try:
                current_span = trace.get_current_span()
                if current_span and current_span.is_recording():
                    span_context = current_span.get_span_context()
                    context.update({
                        'trace_id': format(span_context.trace_id, '032x'),
                        'span_id': format(span_context.span_id, '016x'),
                        'trace_flags': span_context.trace_flags
                    })
            except Exception:
                pass
        
        # Fallback to environment variable trace ID
        trace_id = os.environ.get('TRACE_ID')
        if trace_id and 'trace_id' not in context:
            context['trace_id'] = trace_id
        
        return context
    
    def _create_log_record(self, level: str, message: str, **kwargs) -> Dict[str, Any]:
        """Create structured log record with trace correlation"""
        
        # Base log record
        record = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': level.upper(),
            'logger': self.name,
            'message': message,
            'service': 'osint-platform',
            'component': self.name.split('.')[-1]
        }
        
        # Add trace context
        trace_context = self._get_trace_context()
        if trace_context:
            record['trace'] = trace_context
        
        # Add extra fields
        if kwargs:
            record['extra'] = kwargs
        
        # Add environment context
        record['environment'] = {
            'deployment': os.environ.get('DEPLOYMENT_ENV', 'development'),
            'service_version': os.environ.get('SERVICE_VERSION', '1.0.0'),
            'pod_name': os.environ.get('K8S_POD_NAME'),
            'node_name': os.environ.get('K8S_NODE_NAME')
        }
        
        return record
    
    def debug(self, message: str, **kwargs):
        """Debug level logging with trace correlation"""
        record = self._create_log_record('debug', message, **kwargs)
        self.logger.debug(json.dumps(record))
    
    def info(self, message: str, **kwargs):
        """Info level logging with trace correlation"""
        record = self._create_log_record('info', message, **kwargs)
        self.logger.info(json.dumps(record))
    
    def warning(self, message: str, **kwargs):
        """Warning level logging with trace correlation"""
        record = self._create_log_record('warning', message, **kwargs)
        self.logger.warning(json.dumps(record))
    
    def error(self, message: str, **kwargs):
        """Error level logging with trace correlation"""
        record = self._create_log_record('error', message, **kwargs)
        self.logger.error(json.dumps(record))
    
    def critical(self, message: str, **kwargs):
        """Critical level logging with trace correlation"""
        record = self._create_log_record('critical', message, **kwargs)
        self.logger.critical(json.dumps(record))


class StructuredLoggingFormatter(logging.Formatter):
    """Custom formatter for structured JSON logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON"""
        
        # Check if message is already JSON (from TraceCorrelatedLogger)
        try:
            json.loads(record.getMessage())
            return record.getMessage()
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Create structured format for regular log records
        log_record = {
            'timestamp': datetime.utcfromtimestamp(record.created).isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'service': 'osint-platform',
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_record['exception'] = self.formatException(record.exc_info)
        
        # Add trace context if available
        if OTEL_AVAILABLE:
            try:
                current_span = trace.get_current_span()
                if current_span and current_span.is_recording():
                    span_context = current_span.get_span_context()
                    log_record['trace'] = {
                        'trace_id': format(span_context.trace_id, '032x'),
                        'span_id': format(span_context.span_id, '016x'),
                        'trace_flags': span_context.trace_flags
                    }
            except Exception:
                pass
        
        return json.dumps(log_record)


def configure_structured_logging(
    level: str = "INFO",
    enable_console: bool = True,
    enable_file: bool = False,
    log_file: Optional[str] = None
) -> None:
    """
    Configure structured logging for the OSINT platform
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        enable_console: Enable console output
        enable_file: Enable file output
        log_file: Path to log file (if file logging enabled)
    """
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Create structured formatter
    formatter = StructuredLoggingFormatter()
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
    
    # File handler
    if enable_file and log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    # Configure specific loggers
    loggers_config = {
        'investigation_orchestrator': level,
        'mcp_clients': level,
        'compliance_framework': level,
        'risk_assessment_engine': level,
        'observability': level,
        'job_queue': level,
        'app': level
    }
    
    for logger_name, logger_level in loggers_config.items():
        logger = logging.getLogger(logger_name)
        logger.setLevel(getattr(logging, logger_level.upper()))


def get_structured_logger(name: str) -> TraceCorrelatedLogger:
    """
    Get a structured logger with trace correlation
    
    Args:
        name: Logger name (typically __name__)
    
    Returns:
        TraceCorrelatedLogger instance
    """
    return TraceCorrelatedLogger(name)


def log_operation_timing(operation_name: str):
    """
    Decorator to log operation timing with trace correlation
    
    Args:
        operation_name: Name of the operation being timed
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = get_structured_logger(func.__module__)
            start_time = time.time()
            
            logger.info(f"Starting {operation_name}", 
                       operation=operation_name,
                       function=func.__name__)
            
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                logger.info(f"Completed {operation_name}",
                           operation=operation_name,
                           function=func.__name__,
                           duration_seconds=round(duration, 3),
                           status="success")
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                
                logger.error(f"Failed {operation_name}",
                            operation=operation_name,
                            function=func.__name__,
                            duration_seconds=round(duration, 3),
                            status="error",
                            error_type=type(e).__name__,
                            error_message=str(e))
                raise
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            logger = get_structured_logger(func.__module__)
            start_time = time.time()
            
            logger.info(f"Starting async {operation_name}",
                       operation=operation_name,
                       function=func.__name__)
            
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                
                logger.info(f"Completed async {operation_name}",
                           operation=operation_name,
                           function=func.__name__,
                           duration_seconds=round(duration, 3),
                           status="success")
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                
                logger.error(f"Failed async {operation_name}",
                            operation=operation_name,
                            function=func.__name__,
                            duration_seconds=round(duration, 3),
                            status="error",
                            error_type=type(e).__name__,
                            error_message=str(e))
                raise
        
        # Return appropriate wrapper based on function type
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return wrapper
    
    return decorator


def log_investigation_event(event_type: str, investigation_id: str, **event_data):
    """
    Log investigation-specific events with structured data
    
    Args:
        event_type: Type of investigation event
        investigation_id: Investigation identifier
        **event_data: Additional event data
    """
    logger = get_structured_logger('investigation_events')
    
    logger.info(f"Investigation event: {event_type}",
               event_type=event_type,
               investigation_id=investigation_id,
               **event_data)


def log_mcp_operation(server: str, operation: str, target: str, 
                     status: str = "success", **operation_data):
    """
    Log MCP operation events with structured data
    
    Args:
        server: MCP server name
        operation: Operation name
        target: Investigation target
        status: Operation status (success/error)
        **operation_data: Additional operation data
    """
    logger = get_structured_logger('mcp_operations')
    
    logger.info(f"MCP operation: {server}.{operation}",
               mcp_server=server,
               mcp_operation=operation,
               target=target,
               status=status,
               **operation_data)


def log_compliance_event(framework: str, assessment_result: str, 
                        investigation_id: str, **compliance_data):
    """
    Log compliance assessment events
    
    Args:
        framework: Compliance framework (GDPR, CCPA, etc.)
        assessment_result: Assessment result
        investigation_id: Investigation identifier
        **compliance_data: Additional compliance data
    """
    logger = get_structured_logger('compliance_events')
    
    logger.info(f"Compliance assessment: {framework}",
               compliance_framework=framework,
               assessment_result=assessment_result,
               investigation_id=investigation_id,
               **compliance_data)


def log_security_event(event_type: str, severity: str = "info", **security_data):
    """
    Log security-related events
    
    Args:
        event_type: Type of security event
        severity: Event severity (info/warning/error/critical)
        **security_data: Additional security event data
    """
    logger = get_structured_logger('security_events')
    
    if severity == "critical":
        logger.critical(f"Security event: {event_type}",
                       security_event_type=event_type,
                       severity=severity,
                       **security_data)
    elif severity == "error":
        logger.error(f"Security event: {event_type}",
                    security_event_type=event_type,
                    severity=severity,
                    **security_data)
    elif severity == "warning":
        logger.warning(f"Security event: {event_type}",
                      security_event_type=event_type,
                      severity=severity,
                      **security_data)
    else:
        logger.info(f"Security event: {event_type}",
                   security_event_type=event_type,
                   severity=severity,
                   **security_data)


# Initialize structured logging on module import
if __name__ != "__main__":
    # Configure logging based on environment
    log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
    enable_file = os.environ.get('ENABLE_FILE_LOGGING', 'false').lower() == 'true'
    log_file = os.environ.get('LOG_FILE', '/tmp/osint-platform.log')
    
    configure_structured_logging(
        level=log_level,
        enable_console=True,
        enable_file=enable_file,
        log_file=log_file if enable_file else None
    )