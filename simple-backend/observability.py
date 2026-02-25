"""
OpenTelemetry Instrumentation for OSINT Platform
Provides distributed tracing, metrics, and enhanced observability
"""
import os
import logging
from typing import Optional, Dict, Any, Callable
from datetime import datetime
from functools import wraps

# OpenTelemetry imports
from opentelemetry import trace, metrics, baggage
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.propagate import set_global_textmap
from opentelemetry.propagators.b3 import B3MultiFormat
from opentelemetry.trace import Status, StatusCode
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

# Instrumentation libraries
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.psycopg2 import Psycopg2Instrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
try:
    from opentelemetry.instrumentation.aiohttp import AioHTTPClientInstrumentor
    _AIOHTTP_INSTRUMENTOR_AVAILABLE = True
except ImportError:
    _AIOHTTP_INSTRUMENTOR_AVAILABLE = False  # not packaged on Python 3.11

# Prometheus metrics
from prometheus_client import Counter, Histogram, Gauge, Info, generate_latest

logger = logging.getLogger(__name__)

# Service configuration
SERVICE_NAME_ENV = os.getenv('OTEL_SERVICE_NAME', 'osint-platform-backend')
SERVICE_VERSION_ENV = os.getenv('SERVICE_VERSION', '1.0.0')
DEPLOYMENT_ENV = os.getenv('DEPLOYMENT_ENV', 'development')
OTEL_ENDPOINT = os.getenv('OTEL_EXPORTER_OTLP_ENDPOINT', 'localhost:4317')
OTEL_INSECURE = os.getenv('OTEL_EXPORTER_OTLP_INSECURE', 'true').lower() == 'true'

# Global tracer and meter instances
tracer: Optional[trace.Tracer] = None
meter: Optional[metrics.Meter] = None

# Custom metrics
investigation_counter = None
investigation_duration = None
api_request_counter = None
api_request_duration = None
mcp_operation_counter = None
mcp_operation_duration = None
job_queue_size = None
active_investigations = None
error_counter = None
compliance_check_counter = None


class ObservabilityManager:
    """Manages OpenTelemetry instrumentation for the OSINT Platform"""
    
    def __init__(self):
        self.tracer_provider: Optional[TracerProvider] = None
        self.meter_provider: Optional[MeterProvider] = None
        self.resource: Optional[Resource] = None
        self._initialized = False
    
    def initialize(self, app=None):
        """Initialize OpenTelemetry instrumentation"""
        if self._initialized:
            logger.warning("ObservabilityManager already initialized")
            return
        
        try:
            # Create resource with service information
            self.resource = Resource.create({
                SERVICE_NAME: SERVICE_NAME_ENV,
                SERVICE_VERSION: SERVICE_VERSION_ENV,
                "deployment.environment": DEPLOYMENT_ENV,
                "telemetry.sdk.language": "python",
                "telemetry.sdk.name": "opentelemetry",
                "service.namespace": "osint-platform",
                "service.instance.id": os.getenv('HOSTNAME', 'unknown')
            })
            
            # Initialize tracing
            self._setup_tracing()
            
            # Initialize metrics
            self._setup_metrics()
            
            # Set up propagators for distributed tracing
            set_global_textmap(B3MultiFormat())
            
            # Instrument libraries
            self._instrument_libraries(app)
            
            # Initialize custom metrics
            self._initialize_custom_metrics()
            
            self._initialized = True
            logger.info("OpenTelemetry instrumentation initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize OpenTelemetry: {str(e)}")
    
    def _setup_tracing(self):
        """Set up distributed tracing"""
        global tracer
        
        # Create tracer provider
        self.tracer_provider = TracerProvider(resource=self.resource)
        
        # Configure OTLP exporter
        if OTEL_ENDPOINT != 'disabled':
            otlp_exporter = OTLPSpanExporter(
                endpoint=OTEL_ENDPOINT,
                insecure=OTEL_INSECURE
            )
            
            # Add batch span processor
            span_processor = BatchSpanProcessor(otlp_exporter)
            self.tracer_provider.add_span_processor(span_processor)
        
        # Set global tracer provider
        trace.set_tracer_provider(self.tracer_provider)
        
        # Get tracer instance
        tracer = trace.get_tracer(__name__, SERVICE_VERSION_ENV)
        
        logger.info(f"Tracing configured with endpoint: {OTEL_ENDPOINT}")
    
    def _setup_metrics(self):
        """Set up metrics collection"""
        global meter
        
        # Create metric readers
        readers = []
        
        # OTLP metrics exporter
        if OTEL_ENDPOINT != 'disabled':
            otlp_metric_exporter = OTLPMetricExporter(
                endpoint=OTEL_ENDPOINT,
                insecure=OTEL_INSECURE
            )
            otlp_reader = PeriodicExportingMetricReader(
                exporter=otlp_metric_exporter,
                export_interval_millis=60000  # 1 minute
            )
            readers.append(otlp_reader)
        
        # Prometheus metrics exporter
        prometheus_reader = PrometheusMetricReader()
        readers.append(prometheus_reader)
        
        # Create meter provider
        self.meter_provider = MeterProvider(
            resource=self.resource,
            metric_readers=readers
        )
        
        # Set global meter provider
        metrics.set_meter_provider(self.meter_provider)
        
        # Get meter instance
        meter = metrics.get_meter(__name__, SERVICE_VERSION_ENV)
        
        logger.info("Metrics collection configured")
    
    def _instrument_libraries(self, app=None):
        """Instrument third-party libraries"""
        # Flask instrumentation
        if app:
            FlaskInstrumentor().instrument_app(
                app,
                excluded_urls="/health.*,/metrics"
            )
        
        # HTTP client instrumentation
        RequestsInstrumentor().instrument(
            excluded_urls="localhost:9090.*"  # Exclude Prometheus scraping
        )
        
        # Database instrumentation
        Psycopg2Instrumentor().instrument(
            enable_commenter=True,
            enable_length_normalization=True
        )
        
        # Redis instrumentation
        RedisInstrumentor().instrument()
        
        # Async HTTP client instrumentation (optional — package not available on Python 3.11)
        if _AIOHTTP_INSTRUMENTOR_AVAILABLE:
            AioHTTPClientInstrumentor().instrument()
        
        logger.info("Third-party libraries instrumented")
    
    def _initialize_custom_metrics(self):
        """Initialize custom application metrics"""
        global investigation_counter, investigation_duration, api_request_counter
        global api_request_duration, mcp_operation_counter, mcp_operation_duration
        global job_queue_size, active_investigations, error_counter, compliance_check_counter
        
        if not meter:
            logger.warning("Meter not initialized, skipping custom metrics")
            return
        
        # Investigation metrics
        investigation_counter = meter.create_counter(
            name="osint.investigation.count",
            description="Number of investigations started",
            unit="1"
        )
        
        investigation_duration = meter.create_histogram(
            name="osint.investigation.duration",
            description="Investigation processing duration",
            unit="s"
        )
        
        # API metrics
        api_request_counter = meter.create_counter(
            name="osint.api.request.count",
            description="Number of API requests",
            unit="1"
        )
        
        api_request_duration = meter.create_histogram(
            name="osint.api.request.duration",
            description="API request duration",
            unit="ms"
        )
        
        # MCP operation metrics
        mcp_operation_counter = meter.create_counter(
            name="osint.mcp.operation.count",
            description="Number of MCP operations",
            unit="1"
        )
        
        mcp_operation_duration = meter.create_histogram(
            name="osint.mcp.operation.duration",
            description="MCP operation duration",
            unit="ms"
        )
        
        # Queue metrics
        job_queue_size = meter.create_observable_gauge(
            name="osint.job.queue.size",
            description="Current job queue size",
            unit="1",
            callbacks=[self._get_queue_size]
        )
        
        # Active investigations gauge
        active_investigations = meter.create_observable_gauge(
            name="osint.investigation.active",
            description="Number of active investigations",
            unit="1",
            callbacks=[self._get_active_investigations]
        )
        
        # Error counter
        error_counter = meter.create_counter(
            name="osint.error.count",
            description="Number of errors",
            unit="1"
        )
        
        # Compliance check counter
        compliance_check_counter = meter.create_counter(
            name="osint.compliance.check.count",
            description="Number of compliance checks",
            unit="1"
        )
        
        # Additional enterprise metrics
        self.data_processing_volume = meter.create_counter(
            name="osint.data.processing.volume",
            description="Volume of data processed in bytes",
            unit="byte"
        )
        
        self.api_cost_estimate = meter.create_counter(
            name="osint.api.cost.estimate",
            description="Estimated API costs in USD",
            unit="USD"
        )
        
        self.security_score = meter.create_histogram(
            name="osint.security.score",
            description="Security assessment scores",
            unit="1"
        )
        
        self.compliance_score = meter.create_histogram(
            name="osint.compliance.score",
            description="Compliance assessment scores",
            unit="1"
        )
        
        self.cache_hit_ratio = meter.create_histogram(
            name="osint.cache.hit.ratio",
            description="Cache hit ratio",
            unit="1"
        )
        
        self.external_service_response_time = meter.create_histogram(
            name="osint.external.service.response.time",
            description="External service response times",
            unit="ms"
        )
        
        logger.info("Custom metrics initialized")
    
    def _get_queue_size(self, options):
        """Callback to get current job queue sizes"""
        try:
            from job_queue import job_queue_manager
            stats = job_queue_manager.get_queue_stats()
            
            observations = []
            for queue_name, queue_stats in stats.items():
                if isinstance(queue_stats, dict) and 'length' in queue_stats:
                    observations.append(
                        (queue_stats['length'], {"queue": queue_name})
                    )
            
            return observations
        except Exception as e:
            logger.error(f"Error getting queue size: {str(e)}")
            return []
    
    def _get_active_investigations(self, options):
        """Callback to get active investigation count"""
        try:
            # Query actual investigation count from orchestrator or database
            from investigation_orchestrator import InvestigationOrchestrator
            # This is a placeholder - in production would query the actual count
            active_count = 0  # Would be len(orchestrator.get_active_investigations())
            return [(active_count, {})]
        except Exception as e:
            logger.error(f"Error getting active investigations: {str(e)}")
            return [(0, {})]
    
    def shutdown(self):
        """Shutdown OpenTelemetry providers"""
        if self.tracer_provider:
            self.tracer_provider.shutdown()
        if self.meter_provider:
            self.meter_provider.shutdown()
        self._initialized = False
        logger.info("OpenTelemetry instrumentation shutdown")


# Global observability manager instance
observability_manager = ObservabilityManager()


# Decorators for tracing

def trace_operation(name: str, attributes: Optional[Dict[str, Any]] = None):
    """Decorator to trace function execution"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not tracer:
                return func(*args, **kwargs)
            
            with tracer.start_as_current_span(name) as span:
                # Add custom attributes
                if attributes:
                    for key, value in attributes.items():
                        span.set_attribute(key, value)
                
                # Add function details
                span.set_attribute("function.name", func.__name__)
                span.set_attribute("function.module", func.__module__)
                
                try:
                    result = func(*args, **kwargs)
                    span.set_status(Status(StatusCode.OK))
                    return result
                
                except Exception as e:
                    span.set_status(
                        Status(StatusCode.ERROR, str(e))
                    )
                    span.record_exception(e)
                    raise
        
        return wrapper
    return decorator


def trace_investigation(investigation_type: str):
    """Decorator specifically for investigation operations"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not tracer:
                return func(*args, **kwargs)
            
            with tracer.start_as_current_span("investigation.execute") as span:
                span.set_attribute("investigation.type", investigation_type)
                
                # Extract investigation ID if available
                if args and hasattr(args[0], 'id'):
                    span.set_attribute("investigation.id", args[0].id)
                elif 'investigation_id' in kwargs:
                    span.set_attribute("investigation.id", kwargs['investigation_id'])
                
                # Record start time
                start_time = datetime.utcnow()
                
                try:
                    result = func(*args, **kwargs)
                    
                    # Record metrics
                    if investigation_counter:
                        investigation_counter.add(1, {
                            "type": investigation_type,
                            "status": "success"
                        })
                    
                    if investigation_duration:
                        duration = (datetime.utcnow() - start_time).total_seconds()
                        investigation_duration.record(duration, {
                            "type": investigation_type
                        })
                    
                    span.set_status(Status(StatusCode.OK))
                    return result
                
                except Exception as e:
                    # Record error metrics
                    if investigation_counter:
                        investigation_counter.add(1, {
                            "type": investigation_type,
                            "status": "error"
                        })
                    
                    if error_counter:
                        error_counter.add(1, {
                            "type": "investigation",
                            "investigation_type": investigation_type,
                            "error": e.__class__.__name__
                        })
                    
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    span.record_exception(e)
                    raise
        
        return wrapper
    return decorator


def trace_mcp_operation(mcp_server: str, operation: str):
    """Decorator for MCP operations"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not tracer:
                return func(*args, **kwargs)
            
            with tracer.start_as_current_span("mcp.operation") as span:
                span.set_attribute("mcp.server", mcp_server)
                span.set_attribute("mcp.operation", operation)
                
                start_time = datetime.utcnow()
                
                try:
                    result = func(*args, **kwargs)
                    
                    # Record metrics
                    if mcp_operation_counter:
                        mcp_operation_counter.add(1, {
                            "server": mcp_server,
                            "operation": operation,
                            "status": "success"
                        })
                    
                    if mcp_operation_duration:
                        duration = (datetime.utcnow() - start_time).total_seconds() * 1000
                        mcp_operation_duration.record(duration, {
                            "server": mcp_server,
                            "operation": operation
                        })
                    
                    span.set_status(Status(StatusCode.OK))
                    return result
                
                except Exception as e:
                    # Record error metrics
                    if mcp_operation_counter:
                        mcp_operation_counter.add(1, {
                            "server": mcp_server,
                            "operation": operation,
                            "status": "error"
                        })
                    
                    if error_counter:
                        error_counter.add(1, {
                            "type": "mcp_operation",
                            "server": mcp_server,
                            "operation": operation,
                            "error": e.__class__.__name__
                        })
                    
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    span.record_exception(e)
                    raise
        
        return wrapper
    return decorator


# Utility functions

def add_trace_attributes(**attributes):
    """Add attributes to the current span"""
    span = trace.get_current_span()
    if span and span.is_recording():
        for key, value in attributes.items():
            span.set_attribute(key, value)


def record_error(error: Exception, error_type: str = "unknown"):
    """Record an error in the current span and metrics"""
    span = trace.get_current_span()
    if span and span.is_recording():
        span.record_exception(error)
        span.set_status(Status(StatusCode.ERROR, str(error)))
    
    if error_counter:
        error_counter.add(1, {
            "type": error_type,
            "error": error.__class__.__name__
        })


def get_trace_context() -> Dict[str, str]:
    """Get current trace context for propagation"""
    span = trace.get_current_span()
    if span and span.is_recording():
        span_context = span.get_span_context()
        return {
            "trace_id": format(span_context.trace_id, '032x'),
            "span_id": format(span_context.span_id, '016x'),
            "trace_flags": format(span_context.trace_flags, '02x')
        }
    return {}


def create_child_span(name: str, attributes: Optional[Dict[str, Any]] = None):
    """Create a child span for detailed tracing"""
    if not tracer:
        return None
    
    span = tracer.start_span(name)
    if attributes:
        for key, value in attributes.items():
            span.set_attribute(key, value)
    
    return span


# Prometheus metrics endpoint

def get_metrics():
    """Generate Prometheus metrics"""
    return generate_latest()


def record_investigation_metrics(investigation_type: str, duration_seconds: float, 
                               data_points: int, api_calls: int, cost_estimate: float):
    """Record investigation completion metrics"""
    if investigation_counter:
        investigation_counter.add(1, {"type": investigation_type, "status": "completed"})
    
    if investigation_duration:
        investigation_duration.record(duration_seconds, {"type": investigation_type})
    
    if api_request_counter:
        api_request_counter.add(api_calls, {"source": "investigation"})
    
    if hasattr(observability_manager, 'data_processing_volume'):
        # Estimate data volume (rough calculation)
        estimated_bytes = data_points * 1024  # 1KB per data point estimate
        observability_manager.data_processing_volume.add(estimated_bytes, 
                                                         {"type": investigation_type})
    
    if hasattr(observability_manager, 'api_cost_estimate'):
        observability_manager.api_cost_estimate.add(cost_estimate, {"type": investigation_type})


def record_mcp_operation_metrics(server: str, operation: str, duration_ms: float, 
                                success: bool, response_size_bytes: int = 0):
    """Record MCP operation metrics"""
    status = "success" if success else "error"
    
    if mcp_operation_counter:
        mcp_operation_counter.add(1, {
            "server": server, 
            "operation": operation, 
            "status": status
        })
    
    if mcp_operation_duration:
        mcp_operation_duration.record(duration_ms, {
            "server": server, 
            "operation": operation
        })
    
    if hasattr(observability_manager, 'external_service_response_time'):
        observability_manager.external_service_response_time.record(duration_ms, {
            "service": f"mcp-{server}",
            "operation": operation
        })
    
    if response_size_bytes > 0 and hasattr(observability_manager, 'data_processing_volume'):
        observability_manager.data_processing_volume.add(response_size_bytes, {
            "source": f"mcp-{server}"
        })


def record_compliance_metrics(framework: str, score: float, status: str):
    """Record compliance assessment metrics"""
    if compliance_check_counter:
        compliance_check_counter.add(1, {
            "framework": framework,
            "status": status
        })
    
    if hasattr(observability_manager, 'compliance_score'):
        observability_manager.compliance_score.record(score, {
            "framework": framework
        })


def record_security_metrics(assessment_type: str, score: float, risk_level: str):
    """Record security assessment metrics"""
    if hasattr(observability_manager, 'security_score'):
        observability_manager.security_score.record(score, {
            "assessment_type": assessment_type,
            "risk_level": risk_level
        })


def record_cache_metrics(cache_type: str, hit_ratio: float):
    """Record cache performance metrics"""
    if hasattr(observability_manager, 'cache_hit_ratio'):
        observability_manager.cache_hit_ratio.record(hit_ratio, {
            "cache_type": cache_type
        })


def record_api_metrics(endpoint: str, method: str, status_code: int, 
                      duration_ms: float, response_size_bytes: int = 0):
    """Record API endpoint metrics"""
    if api_request_counter:
        api_request_counter.add(1, {
            "endpoint": endpoint,
            "method": method,
            "status_code": str(status_code)
        })
    
    if api_request_duration:
        api_request_duration.record(duration_ms, {
            "endpoint": endpoint,
            "method": method
        })
    
    if response_size_bytes > 0 and hasattr(observability_manager, 'data_processing_volume'):
        observability_manager.data_processing_volume.add(response_size_bytes, {
            "source": "api-response"
        })


# Initialize on import
if os.getenv('OTEL_ENABLED', 'true').lower() == 'true':
    logger.info("OpenTelemetry enabled, initializing...")
else:
    logger.info("OpenTelemetry disabled via OTEL_ENABLED environment variable")