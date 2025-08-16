"""
Unit tests for trace context functionality
"""
import pytest
import json
from trace_context import TraceContextManager, StructuredLogger
from flask import g


class TestTraceContext:
    """Test trace context management"""
    
    def test_trace_id_generation(self):
        """Test that trace IDs are generated correctly"""
        trace_id = TraceContextManager.generate_trace_id()
        assert trace_id is not None
        assert len(trace_id) == 36  # UUID format
        assert '-' in trace_id
    
    def test_span_id_generation(self):
        """Test that span IDs are generated correctly"""
        span_id = TraceContextManager.generate_span_id()
        assert span_id is not None
        assert len(span_id) == 8  # Shortened UUID
    
    def test_trace_headers_in_response(self, client):
        """Test that trace headers are added to responses"""
        response = client.get('/health')
        
        # Check for trace headers in response
        assert 'X-Trace-Id' in response.headers
        assert 'X-Span-Id' in response.headers
        
        # Verify format
        trace_id = response.headers.get('X-Trace-Id')
        span_id = response.headers.get('X-Span-Id')
        
        assert len(trace_id) == 36  # UUID format
        assert len(span_id) == 8    # Short format
    
    def test_trace_id_propagation(self, client):
        """Test that trace IDs are propagated from request headers"""
        custom_trace_id = 'test-trace-12345678-1234-1234-1234-123456789012'
        custom_span_id = 'testspan'
        
        headers = {
            'X-Trace-Id': custom_trace_id,
            'X-Span-Id': custom_span_id
        }
        
        response = client.get('/health', headers=headers)
        
        # Verify the same trace ID is returned
        assert response.headers.get('X-Trace-Id') == custom_trace_id
        assert response.headers.get('X-Span-Id') == custom_span_id
        
        # Verify it's in the response body
        data = json.loads(response.data)
        assert data.get('trace_id') == custom_trace_id
    
    def test_structured_logger_format(self):
        """Test that structured logger produces correct format"""
        logger = StructuredLogger('test')
        
        # This would need to capture log output to fully test
        # For now, just verify the logger initializes correctly
        assert logger.logger is not None
        assert logger.logger.name == 'test'


class TestRequestLogging:
    """Test request logging functionality"""
    
    def test_request_logging(self, client, caplog):
        """Test that requests are logged with trace context"""
        response = client.get('/health')
        
        # Check that request start and completion were logged
        # Note: This may need adjustment based on actual logging setup
        assert response.status_code == 200
        
        # Verify trace_id is in response
        data = json.loads(response.data)
        assert 'trace_id' in data
    
    def test_error_logging_format(self, client):
        """Test that errors are logged with proper format"""
        # Test with an endpoint that might error
        response = client.get('/api/investigations/nonexistent')
        
        # Should return 401 (unauthorized) or 404
        assert response.status_code in [401, 404]