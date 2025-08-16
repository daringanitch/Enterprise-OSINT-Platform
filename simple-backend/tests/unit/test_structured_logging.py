"""
Unit tests for structured logging functionality
"""
import pytest
import os
import json
import logging
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from io import StringIO

from structured_logging import (
    TraceCorrelatedLogger, StructuredLoggingFormatter, configure_structured_logging,
    get_structured_logger, log_operation_timing, log_investigation_event,
    log_mcp_operation, log_compliance_event, log_security_event
)


class TestTraceCorrelatedLogger:
    """Test TraceCorrelatedLogger functionality"""
    
    def test_logger_initialization(self):
        """Test logger initialization"""
        logger = TraceCorrelatedLogger("test.logger")
        
        assert logger.name == "test.logger"
        assert logger.logger.name == "test.logger"
    
    @patch('structured_logging.os.environ')
    def test_get_trace_context_from_environment(self, mock_environ):
        """Test trace context extraction from environment"""
        mock_environ.get.return_value = "test-trace-id-123"
        
        logger = TraceCorrelatedLogger("test")
        context = logger._get_trace_context()
        
        assert "trace_id" in context
        assert context["trace_id"] == "test-trace-id-123"
    
    @patch('structured_logging.OTEL_AVAILABLE', True)
    @patch('structured_logging.trace')
    def test_get_trace_context_from_otel(self, mock_trace):
        """Test trace context extraction from OpenTelemetry"""
        mock_span = Mock()
        mock_span.is_recording.return_value = True
        mock_span_context = Mock()
        mock_span_context.trace_id = 12345678901234567890123456789012
        mock_span_context.span_id = 1234567890123456
        mock_span_context.trace_flags = 1
        mock_span.get_span_context.return_value = mock_span_context
        mock_trace.get_current_span.return_value = mock_span
        
        logger = TraceCorrelatedLogger("test")
        context = logger._get_trace_context()
        
        assert "trace_id" in context
        assert "span_id" in context
        assert "trace_flags" in context
    
    def test_create_log_record(self):
        """Test log record creation"""
        logger = TraceCorrelatedLogger("test.logger")
        
        record = logger._create_log_record("info", "Test message", extra_field="extra_value")
        
        assert record["level"] == "INFO"
        assert record["message"] == "Test message"
        assert record["logger"] == "test.logger"
        assert record["service"] == "osint-platform"
        assert record["component"] == "logger"
        assert "timestamp" in record
        assert "environment" in record
        assert record["extra"]["extra_field"] == "extra_value"
    
    @patch('structured_logging.TraceCorrelatedLogger._create_log_record')
    def test_info_logging(self, mock_create_record):
        """Test info level logging"""
        mock_record = {"level": "INFO", "message": "test"}
        mock_create_record.return_value = mock_record
        
        logger = TraceCorrelatedLogger("test")
        logger.logger = Mock()
        
        logger.info("Test message", extra="data")
        
        mock_create_record.assert_called_once_with("info", "Test message", extra="data")
        logger.logger.info.assert_called_once_with(json.dumps(mock_record))
    
    @patch('structured_logging.TraceCorrelatedLogger._create_log_record')
    def test_error_logging(self, mock_create_record):
        """Test error level logging"""
        mock_record = {"level": "ERROR", "message": "test error"}
        mock_create_record.return_value = mock_record
        
        logger = TraceCorrelatedLogger("test")
        logger.logger = Mock()
        
        logger.error("Test error", error_code=500)
        
        mock_create_record.assert_called_once_with("error", "Test error", error_code=500)
        logger.logger.error.assert_called_once_with(json.dumps(mock_record))


class TestStructuredLoggingFormatter:
    """Test StructuredLoggingFormatter functionality"""
    
    def test_format_json_message(self):
        """Test formatting of already JSON message"""
        formatter = StructuredLoggingFormatter()
        
        json_message = '{"level": "INFO", "message": "test"}'
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg=json_message, args=(), exc_info=None
        )
        
        result = formatter.format(record)
        assert result == json_message
    
    def test_format_regular_message(self):
        """Test formatting of regular log message"""
        formatter = StructuredLoggingFormatter()
        
        record = logging.LogRecord(
            name="test.logger", level=logging.INFO, pathname="/test/path.py", 
            lineno=42, msg="Regular log message", args=(), exc_info=None,
            func="test_function"
        )
        record.module = "test_module"
        
        result = formatter.format(record)
        formatted_record = json.loads(result)
        
        assert formatted_record["level"] == "INFO"
        assert formatted_record["message"] == "Regular log message"
        assert formatted_record["logger"] == "test.logger"
        assert formatted_record["module"] == "test_module"
        assert formatted_record["function"] == "test_function"
        assert formatted_record["line"] == 42
        assert "timestamp" in formatted_record
    
    def test_format_with_exception(self):
        """Test formatting with exception info"""
        formatter = StructuredLoggingFormatter()
        
        try:
            raise ValueError("Test exception")
        except ValueError:
            import sys
            exc_info = sys.exc_info()
        
        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="", lineno=0,
            msg="Error with exception", args=(), exc_info=exc_info
        )
        record.module = "test"
        record.funcName = "test_func"
        
        result = formatter.format(record)
        formatted_record = json.loads(result)
        
        assert "exception" in formatted_record
        assert "ValueError" in formatted_record["exception"]


class TestLoggingConfiguration:
    """Test logging configuration functions"""
    
    @patch('structured_logging.logging.getLogger')
    def test_configure_structured_logging(self, mock_get_logger):
        """Test structured logging configuration"""
        mock_root_logger = Mock()
        mock_get_logger.return_value = mock_root_logger
        
        configure_structured_logging(
            level="DEBUG",
            enable_console=True,
            enable_file=False
        )
        
        mock_root_logger.setLevel.assert_called_with(logging.DEBUG)
        mock_root_logger.handlers.clear.assert_called_once()
        assert mock_root_logger.addHandler.call_count >= 1
    
    def test_get_structured_logger(self):
        """Test getting structured logger"""
        logger = get_structured_logger("test.module")
        
        assert isinstance(logger, TraceCorrelatedLogger)
        assert logger.name == "test.module"


class TestLoggingDecorators:
    """Test logging decorators and utility functions"""
    
    @patch('structured_logging.get_structured_logger')
    @patch('structured_logging.time.time')
    def test_log_operation_timing_sync(self, mock_time, mock_get_logger):
        """Test operation timing decorator for sync functions"""
        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger
        mock_time.side_effect = [1000.0, 1001.5]  # Start and end times
        
        @log_operation_timing("test_operation")
        def test_function():
            return "result"
        
        result = test_function()
        
        assert result == "result"
        assert mock_logger.info.call_count == 2  # Start and completion
        
        # Check start log
        start_call = mock_logger.info.call_args_list[0]
        assert "Starting test_operation" in start_call[0][0]
        
        # Check completion log
        completion_call = mock_logger.info.call_args_list[1]
        assert "Completed test_operation" in completion_call[0][0]
        assert completion_call[1]["duration_seconds"] == 1.5
    
    @patch('structured_logging.get_structured_logger')
    @patch('structured_logging.time.time')
    def test_log_operation_timing_with_exception(self, mock_time, mock_get_logger):
        """Test operation timing decorator with exception"""
        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger
        mock_time.side_effect = [1000.0, 1001.0]
        
        @log_operation_timing("failing_operation")
        def failing_function():
            raise ValueError("Test error")
        
        with pytest.raises(ValueError):
            failing_function()
        
        # Should log start and error
        assert mock_logger.info.call_count == 1  # Start
        assert mock_logger.error.call_count == 1  # Error
        
        error_call = mock_logger.error.call_args_list[0]
        assert "Failed failing_operation" in error_call[0][0]
        assert error_call[1]["status"] == "error"
        assert error_call[1]["error_type"] == "ValueError"
    
    @patch('structured_logging.get_structured_logger')
    def test_log_investigation_event(self, mock_get_logger):
        """Test investigation event logging"""
        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger
        
        log_investigation_event("investigation_started", "inv_123", 
                              target="example.com", priority="high")
        
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        assert "Investigation event: investigation_started" in call_args[0][0]
        assert call_args[1]["investigation_id"] == "inv_123"
        assert call_args[1]["target"] == "example.com"
        assert call_args[1]["priority"] == "high"
    
    @patch('structured_logging.get_structured_logger')
    def test_log_mcp_operation(self, mock_get_logger):
        """Test MCP operation logging"""
        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger
        
        log_mcp_operation("infrastructure", "whois_lookup", "example.com",
                         status="success", duration_ms=250)
        
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        assert "MCP operation: infrastructure.whois_lookup" in call_args[0][0]
        assert call_args[1]["mcp_server"] == "infrastructure"
        assert call_args[1]["mcp_operation"] == "whois_lookup"
        assert call_args[1]["target"] == "example.com"
        assert call_args[1]["status"] == "success"
        assert call_args[1]["duration_ms"] == 250
    
    @patch('structured_logging.get_structured_logger')
    def test_log_compliance_event(self, mock_get_logger):
        """Test compliance event logging"""
        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger
        
        log_compliance_event("GDPR", "compliant", "inv_123", score=85.5)
        
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        assert "Compliance assessment: GDPR" in call_args[0][0]
        assert call_args[1]["compliance_framework"] == "GDPR"
        assert call_args[1]["assessment_result"] == "compliant"
        assert call_args[1]["investigation_id"] == "inv_123"
        assert call_args[1]["score"] == 85.5
    
    @patch('structured_logging.get_structured_logger')
    def test_log_security_event_critical(self, mock_get_logger):
        """Test critical security event logging"""
        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger
        
        log_security_event("unauthorized_access", severity="critical", 
                          user_id="user123", ip_address="192.168.1.100")
        
        mock_logger.critical.assert_called_once()
        call_args = mock_logger.critical.call_args
        assert "Security event: unauthorized_access" in call_args[0][0]
        assert call_args[1]["security_event_type"] == "unauthorized_access"
        assert call_args[1]["severity"] == "critical"
        assert call_args[1]["user_id"] == "user123"
        assert call_args[1]["ip_address"] == "192.168.1.100"
    
    @patch('structured_logging.get_structured_logger')
    def test_log_security_event_info(self, mock_get_logger):
        """Test info level security event logging"""
        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger
        
        log_security_event("user_login", severity="info", user_id="user123")
        
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        assert "Security event: user_login" in call_args[0][0]
        assert call_args[1]["severity"] == "info"


class TestEnvironmentConfiguration:
    """Test environment-based configuration"""
    
    @patch.dict(os.environ, {
        'LOG_LEVEL': 'DEBUG',
        'ENABLE_FILE_LOGGING': 'true',
        'LOG_FILE': '/tmp/test.log',
        'DEPLOYMENT_ENV': 'testing',
        'SERVICE_VERSION': '2.0.0'
    })
    def test_environment_configuration(self):
        """Test configuration from environment variables"""
        logger = TraceCorrelatedLogger("test")
        record = logger._create_log_record("info", "test message")
        
        assert record["environment"]["deployment"] == "testing"
        assert record["environment"]["service_version"] == "2.0.0"
    
    @patch('structured_logging.configure_structured_logging')
    def test_module_import_configuration(self, mock_configure):
        """Test that logging is configured on module import"""
        # This would be tested by importing the module
        # The actual test would depend on the import behavior
        pass


class TestAsyncFunctionTiming:
    """Test async function timing decorator"""
    
    @patch('structured_logging.get_structured_logger')
    @patch('structured_logging.time.time')
    @pytest.mark.asyncio
    async def test_log_operation_timing_async(self, mock_time, mock_get_logger):
        """Test operation timing decorator for async functions"""
        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger
        mock_time.side_effect = [1000.0, 1002.0]
        
        @log_operation_timing("async_operation")
        async def async_test_function():
            return "async_result"
        
        result = await async_test_function()
        
        assert result == "async_result"
        assert mock_logger.info.call_count == 2
        
        # Check completion log includes async indication
        completion_call = mock_logger.info.call_args_list[1]
        assert "Completed async async_operation" in completion_call[0][0]
        assert completion_call[1]["duration_seconds"] == 2.0


class TestErrorHandling:
    """Test error handling in logging components"""
    
    @patch('structured_logging.OTEL_AVAILABLE', True)
    @patch('structured_logging.trace')
    def test_trace_context_error_handling(self, mock_trace):
        """Test graceful error handling in trace context extraction"""
        mock_trace.get_current_span.side_effect = Exception("OTEL error")
        
        logger = TraceCorrelatedLogger("test")
        context = logger._get_trace_context()
        
        # Should not raise exception, should return empty context
        assert isinstance(context, dict)
    
    def test_json_formatting_error_handling(self):
        """Test error handling in JSON formatting"""
        formatter = StructuredLoggingFormatter()
        
        # Create a record that might cause JSON serialization issues
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="Test message", args=(), exc_info=None
        )
        record.module = "test"
        record.funcName = "test"
        
        # Should not raise exception
        result = formatter.format(record)
        assert isinstance(result, str)
        
        # Should be valid JSON
        json.loads(result)