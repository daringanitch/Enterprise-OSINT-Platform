"""
Unit tests for OpenTelemetry observability
"""
import pytest
import os
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from observability import (
    ObservabilityManager, trace_operation, trace_investigation, 
    trace_mcp_operation, add_trace_attributes, record_error,
    get_trace_context, create_child_span
)


class TestObservabilityManager:
    """Test ObservabilityManager functionality"""
    
    def test_observability_manager_init(self):
        """Test ObservabilityManager initialization"""
        manager = ObservabilityManager()
        
        assert manager.tracer_provider is None
        assert manager.meter_provider is None
        assert manager._initialized is False
    
    @patch('observability.TracerProvider')
    @patch('observability.MeterProvider')
    @patch('observability.Resource')
    def test_initialize_success(self, mock_resource, mock_meter_provider, mock_tracer_provider):
        """Test successful initialization"""
        manager = ObservabilityManager()
        
        mock_app = Mock()
        manager.initialize(mock_app)
        
        assert manager._initialized is True
        mock_resource.create.assert_called_once()
        assert manager.tracer_provider is not None
        assert manager.meter_provider is not None
    
    def test_initialize_twice_warning(self):
        """Test that initializing twice logs warning"""
        manager = ObservabilityManager()
        manager._initialized = True
        
        with patch('observability.logger') as mock_logger:
            manager.initialize()
            mock_logger.warning.assert_called_with("ObservabilityManager already initialized")
    
    @patch('observability.TracerProvider')
    @patch('observability.OTLPSpanExporter')
    def test_setup_tracing(self, mock_exporter, mock_tracer_provider):
        """Test tracing setup"""
        manager = ObservabilityManager()
        manager.resource = Mock()
        
        manager._setup_tracing()
        
        mock_tracer_provider.assert_called_once_with(resource=manager.resource)
        mock_exporter.assert_called_once()
    
    @patch('observability.MeterProvider')
    @patch('observability.OTLPMetricExporter')
    @patch('observability.PrometheusMetricReader')
    def test_setup_metrics(self, mock_prom_reader, mock_otlp_exporter, mock_meter_provider):
        """Test metrics setup"""
        manager = ObservabilityManager()
        manager.resource = Mock()
        
        manager._setup_metrics()
        
        mock_meter_provider.assert_called_once()
        mock_otlp_exporter.assert_called_once()
        mock_prom_reader.assert_called_once()
    
    @patch('observability.FlaskInstrumentor')
    @patch('observability.RequestsInstrumentor')
    @patch('observability.Psycopg2Instrumentor')
    @patch('observability.RedisInstrumentor')
    def test_instrument_libraries(self, mock_redis, mock_psycopg2, mock_requests, mock_flask):
        """Test library instrumentation"""
        manager = ObservabilityManager()
        mock_app = Mock()
        
        manager._instrument_libraries(mock_app)
        
        mock_flask.return_value.instrument_app.assert_called_once_with(
            mock_app, excluded_urls="/health.*,/metrics"
        )
        mock_requests.return_value.instrument.assert_called_once()
        mock_psycopg2.return_value.instrument.assert_called_once()
        mock_redis.return_value.instrument.assert_called_once()
    
    def test_shutdown(self):
        """Test shutdown process"""
        manager = ObservabilityManager()
        manager.tracer_provider = Mock()
        manager.meter_provider = Mock()
        manager._initialized = True
        
        manager.shutdown()
        
        manager.tracer_provider.shutdown.assert_called_once()
        manager.meter_provider.shutdown.assert_called_once()
        assert manager._initialized is False


class TestTracingDecorators:
    """Test tracing decorators"""
    
    @patch('observability.tracer')
    def test_trace_operation_decorator(self, mock_tracer):
        """Test trace_operation decorator"""
        mock_span = Mock()
        mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span
        
        @trace_operation("test.operation", {"attr1": "value1"})
        def test_function(x, y):
            return x + y
        
        result = test_function(2, 3)
        
        assert result == 5
        mock_tracer.start_as_current_span.assert_called_once_with("test.operation")
        mock_span.set_attribute.assert_any_call("attr1", "value1")
        mock_span.set_attribute.assert_any_call("function.name", "test_function")
    
    @patch('observability.tracer')
    def test_trace_operation_exception(self, mock_tracer):
        """Test trace_operation with exception"""
        mock_span = Mock()
        mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span
        
        @trace_operation("test.operation")
        def test_function():
            raise ValueError("Test error")
        
        with pytest.raises(ValueError):
            test_function()
        
        mock_span.record_exception.assert_called_once()
        mock_span.set_status.assert_called()
    
    @patch('observability.tracer')
    @patch('observability.investigation_counter')
    @patch('observability.investigation_duration')
    def test_trace_investigation_decorator(self, mock_duration, mock_counter, mock_tracer):
        """Test trace_investigation decorator"""
        mock_span = Mock()
        mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span
        
        @trace_investigation("comprehensive")
        def investigate(investigation_id="inv_123"):
            return "completed"
        
        result = investigate()
        
        assert result == "completed"
        mock_tracer.start_as_current_span.assert_called_once_with("investigation.execute")
        mock_span.set_attribute.assert_any_call("investigation.type", "comprehensive")
        mock_counter.add.assert_called_once()
        mock_duration.record.assert_called_once()
    
    @patch('observability.tracer')
    @patch('observability.mcp_operation_counter')
    @patch('observability.mcp_operation_duration')
    def test_trace_mcp_operation_decorator(self, mock_duration, mock_counter, mock_tracer):
        """Test trace_mcp_operation decorator"""
        mock_span = Mock()
        mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span
        
        @trace_mcp_operation("infrastructure", "whois_lookup")
        def mcp_operation():
            return {"domain": "example.com"}
        
        result = mcp_operation()
        
        assert result == {"domain": "example.com"}
        mock_tracer.start_as_current_span.assert_called_once_with("mcp.operation")
        mock_span.set_attribute.assert_any_call("mcp.server", "infrastructure")
        mock_span.set_attribute.assert_any_call("mcp.operation", "whois_lookup")
        mock_counter.add.assert_called_once()
        mock_duration.record.assert_called_once()


class TestUtilityFunctions:
    """Test observability utility functions"""
    
    @patch('observability.trace')
    def test_add_trace_attributes(self, mock_trace):
        """Test adding trace attributes"""
        mock_span = Mock()
        mock_span.is_recording.return_value = True
        mock_trace.get_current_span.return_value = mock_span
        
        add_trace_attributes(key1="value1", key2="value2")
        
        mock_span.set_attribute.assert_any_call("key1", "value1")
        mock_span.set_attribute.assert_any_call("key2", "value2")
    
    @patch('observability.trace')
    @patch('observability.error_counter')
    def test_record_error(self, mock_error_counter, mock_trace):
        """Test error recording"""
        mock_span = Mock()
        mock_span.is_recording.return_value = True
        mock_trace.get_current_span.return_value = mock_span
        
        error = ValueError("Test error")
        record_error(error, "test_error")
        
        mock_span.record_exception.assert_called_once_with(error)
        mock_span.set_status.assert_called_once()
        mock_error_counter.add.assert_called_once_with(1, {
            "type": "test_error",
            "error": "ValueError"
        })
    
    @patch('observability.trace')
    def test_get_trace_context(self, mock_trace):
        """Test getting trace context"""
        mock_span = Mock()
        mock_span.is_recording.return_value = True
        mock_span_context = Mock()
        mock_span_context.trace_id = 12345
        mock_span_context.span_id = 67890
        mock_span_context.trace_flags = 1
        mock_span.get_span_context.return_value = mock_span_context
        mock_trace.get_current_span.return_value = mock_span
        
        context = get_trace_context()
        
        assert "trace_id" in context
        assert "span_id" in context
        assert "trace_flags" in context
    
    @patch('observability.tracer')
    def test_create_child_span(self, mock_tracer):
        """Test creating child span"""
        mock_span = Mock()
        mock_tracer.start_span.return_value = mock_span
        
        span = create_child_span("child.operation", {"attr": "value"})
        
        assert span == mock_span
        mock_tracer.start_span.assert_called_once_with("child.operation")
        mock_span.set_attribute.assert_called_once_with("attr", "value")


class TestMetricsCallbacks:
    """Test metrics callback functions"""
    
    @pytest.mark.skip(reason="job_queue_manager not exported from observability module")
    def test_get_queue_size_callback(self):
        """Test queue size callback"""
        manager = ObservabilityManager()

        with patch('job_queue.job_queue_manager') as mock_queue_manager:
            mock_queue_manager.get_queue_stats.return_value = {
                'investigations': {'length': 5},
                'reports': {'length': 2}
            }
            
            observations = manager._get_queue_size(None)
            
            assert len(observations) == 2
            assert observations[0] == (5, {"queue": "investigations"})
            assert observations[1] == (2, {"queue": "reports"})
    
    @pytest.mark.skip(reason="job_queue_manager not exported from observability module")
    def test_get_queue_size_error(self):
        """Test queue size callback error handling"""
        manager = ObservabilityManager()

        with patch('job_queue.job_queue_manager') as mock_queue_manager:
            mock_queue_manager.get_queue_stats.side_effect = Exception("Queue error")
            
            observations = manager._get_queue_size(None)
            
            assert observations == []
    
    def test_get_active_investigations_callback(self):
        """Test active investigations callback"""
        manager = ObservabilityManager()
        
        observations = manager._get_active_investigations(None)
        
        # Should return placeholder for now
        assert observations == [(0, {})]


class TestEnvironmentConfiguration:
    """Test environment-based configuration"""
    
    @pytest.mark.skip(reason="Module-level constants loaded before patch - environment variables set at module load time")
    def test_service_configuration(self):
        """Test service configuration from environment"""
        with patch.dict(os.environ, {
            'OTEL_SERVICE_NAME': 'test-service',
            'SERVICE_VERSION': '2.0.0',
            'DEPLOYMENT_ENV': 'testing',
            'OTEL_EXPORTER_OTLP_ENDPOINT': 'otel:4317',
            'OTEL_EXPORTER_OTLP_INSECURE': 'false'
        }):
            from observability import (
                SERVICE_NAME_ENV, SERVICE_VERSION_ENV,
                DEPLOYMENT_ENV, OTEL_ENDPOINT, OTEL_INSECURE
            )

            assert SERVICE_NAME_ENV == 'test-service'
            assert SERVICE_VERSION_ENV == '2.0.0'
            assert DEPLOYMENT_ENV == 'testing'
            assert OTEL_ENDPOINT == 'otel:4317'
            assert OTEL_INSECURE is False
    
    @pytest.mark.skip(reason="Module-level constants loaded before patch - OTEL_ENABLED checked at module load time")
    def test_otel_disabled(self):
        """Test OTEL can be disabled via environment"""
        with patch.dict(os.environ, {'OTEL_ENABLED': 'false'}):
            # Importing should not initialize when disabled
            with patch('observability.logger') as mock_logger:
                import observability
                mock_logger.info.assert_called_with(
                    "OpenTelemetry disabled via OTEL_ENABLED environment variable"
                )


class TestPrometheusMetrics:
    """Test Prometheus metrics integration"""
    
    @patch('observability.generate_latest')
    def test_get_metrics(self, mock_generate):
        """Test Prometheus metrics generation"""
        from observability import get_metrics
        
        mock_generate.return_value = b"# HELP test_metric\n# TYPE test_metric counter\ntest_metric 1.0\n"
        
        metrics = get_metrics()
        
        assert metrics == mock_generate.return_value
        mock_generate.assert_called_once()


class TestTracingIntegration:
    """Test tracing integration scenarios"""
    
    @patch('observability.tracer')
    def test_nested_spans(self, mock_tracer):
        """Test nested span creation"""
        parent_span = Mock()
        child_span = Mock()
        
        mock_tracer.start_as_current_span.return_value.__enter__.return_value = parent_span
        mock_tracer.start_span.return_value = child_span
        
        @trace_operation("parent.operation")
        def parent_function():
            span = create_child_span("child.operation")
            return span
        
        result = parent_function()
        
        assert result == child_span
        mock_tracer.start_as_current_span.assert_called_once_with("parent.operation")
        mock_tracer.start_span.assert_called_once_with("child.operation")
    
    def test_no_tracer_graceful_degradation(self):
        """Test graceful degradation when tracer not available"""
        with patch('observability.tracer', None):
            @trace_operation("test.operation")
            def test_function():
                return "success"
            
            # Should work without tracer
            result = test_function()
            assert result == "success"