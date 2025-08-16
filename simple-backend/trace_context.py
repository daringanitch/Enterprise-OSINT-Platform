#!/usr/bin/env python3
"""
Trace Context Management for OSINT Platform
Implements correlation IDs for request tracing across the system
"""

import uuid
import logging
from flask import g, request
from functools import wraps
from typing import Optional, Dict, Any
import json
from datetime import datetime

class TraceContextManager:
    """Manages trace context throughout request lifecycle"""
    
    TRACE_HEADER = 'X-Trace-Id'
    SPAN_HEADER = 'X-Span-Id'
    
    @staticmethod
    def generate_trace_id() -> str:
        """Generate a new trace ID"""
        return str(uuid.uuid4())
    
    @staticmethod
    def generate_span_id() -> str:
        """Generate a new span ID"""
        return str(uuid.uuid4())[:8]
    
    @staticmethod
    def get_or_create_trace_id() -> str:
        """Get trace ID from request header or create new one"""
        if hasattr(g, 'trace_id') and g.trace_id:
            return g.trace_id
            
        # Check request headers
        trace_id = request.headers.get(TraceContextManager.TRACE_HEADER)
        if not trace_id:
            trace_id = TraceContextManager.generate_trace_id()
        
        g.trace_id = trace_id
        return trace_id
    
    @staticmethod
    def get_current_span_id() -> str:
        """Get current span ID or create new one"""
        if hasattr(g, 'span_id') and g.span_id:
            return g.span_id
            
        span_id = request.headers.get(TraceContextManager.SPAN_HEADER)
        if not span_id:
            span_id = TraceContextManager.generate_span_id()
        
        g.span_id = span_id
        return span_id


class StructuredLogger:
    """Structured JSON logger with trace context"""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self._setup_json_formatter()
    
    def _setup_json_formatter(self):
        """Configure JSON formatter for structured logging"""
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def _add_context(self, extra: Dict[str, Any]) -> Dict[str, Any]:
        """Add trace context to log extra fields"""
        context = {
            'trace_id': getattr(g, 'trace_id', None),
            'span_id': getattr(g, 'span_id', None),
            'user_id': getattr(g, 'user_id', None),
            'service': 'osint-backend',
            'timestamp': datetime.utcnow().isoformat(),
        }
        
        # Add request context if available
        if request:
            context.update({
                'method': request.method,
                'path': request.path,
                'remote_addr': request.remote_addr,
                'user_agent': request.headers.get('User-Agent'),
            })
        
        # Merge with provided extra fields
        context.update(extra or {})
        return context
    
    def info(self, msg: str, **kwargs):
        """Log info with trace context"""
        extra = self._add_context(kwargs)
        self.logger.info(msg, extra={'structured': extra})
    
    def error(self, msg: str, error: Optional[Exception] = None, **kwargs):
        """Log error with trace context"""
        extra = self._add_context(kwargs)
        if error:
            extra['error_type'] = type(error).__name__
            extra['error_message'] = str(error)
        self.logger.error(msg, extra={'structured': extra})
    
    def warning(self, msg: str, **kwargs):
        """Log warning with trace context"""
        extra = self._add_context(kwargs)
        self.logger.warning(msg, extra={'structured': extra})
    
    def debug(self, msg: str, **kwargs):
        """Log debug with trace context"""
        extra = self._add_context(kwargs)
        self.logger.debug(msg, extra={'structured': extra})


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def format(self, record):
        """Format log record as JSON"""
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        
        # Add structured data if present
        if hasattr(record, 'structured'):
            log_data.update(record.structured)
        
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)


def trace_context(f):
    """Decorator to ensure trace context is set for a request"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        TraceContextManager.get_or_create_trace_id()
        TraceContextManager.get_current_span_id()
        return f(*args, **kwargs)
    return decorated_function


def inject_trace_headers(response):
    """Inject trace headers into response"""
    if hasattr(g, 'trace_id'):
        response.headers[TraceContextManager.TRACE_HEADER] = g.trace_id
    if hasattr(g, 'span_id'):
        response.headers[TraceContextManager.SPAN_HEADER] = g.span_id
    return response


# Create a global logger instance
logger = StructuredLogger(__name__)