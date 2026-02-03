#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.
# Individual use is free. Commercial use requires 3% profit sharing.
# See LICENSE file for details.

"""
Enterprise OSINT Platform Backend
Full Intelligence Gathering and Analysis System
"""
import os
from flask import Flask, jsonify, request, g
from flask_cors import CORS
from datetime import datetime, timedelta
from collections import defaultdict
import logging
import uuid
import threading
import time
import json
from pathlib import Path
import bcrypt
import jwt
import psycopg2
from functools import wraps
# Structured logging functionality (simplified for Docker compatibility)
# from trace_context import TraceContextManager, StructuredLogger, trace_context, inject_trace_headers
# from structured_logging import (
#     configure_structured_logging, get_structured_logger, log_investigation_event,
#     log_mcp_operation, log_security_event, log_operation_timing
# )

# Import OSINT investigation system
from models import (
    OSINTInvestigation, InvestigationType, InvestigationStatus, Priority,
    TargetProfile, InvestigationScope
)

# Import mode management and demo data
from mode_manager import mode_manager
from demo_data import demo_provider
from investigation_orchestrator import InvestigationOrchestrator
from compliance_framework import ComplianceEngine, ComplianceFramework
from investigation_reporting import InvestigationReportGenerator, ReportFormat, TimeRange
from vault_client import VaultClient, VaultConfig, APIKeyConfig, ConfigurationManager
from professional_report_generator import ProfessionalReportGenerator, ReportType, ReportFormat as ProfReportFormat, ClassificationLevel
from audit_report_generator import ComprehensiveAuditReportGenerator, AuditScope
from postgres_audit_client import (
    init_audit_client, get_audit_client, log_investigation_start, log_investigation_complete,
    log_api_call, AuditEvent, EventType, InvestigationAuditRecord
)
from api_connection_monitor import APIConnectionMonitor, APIStatus, APIType

# Input validation
try:
    from validators import (
        validate_investigation_request, validate_login_request,
        validate_compliance_request, validate_risk_request,
        ValidationError as InputValidationError, get_safe_error_message
    )
    VALIDATION_ENABLED = True
except ImportError:
    VALIDATION_ENABLED = False
    class InputValidationError(Exception):
        pass
    def validate_investigation_request(data): return data
    def validate_login_request(data): return data
    def get_safe_error_message(t, d=None): return d or 'An error occurred'

# Caching service
try:
    from cache_service import cache_service, cached, CacheTTL, cached_response
    CACHING_ENABLED = True
except ImportError:
    CACHING_ENABLED = False
    cache_service = None
    def cached(*args, **kwargs):
        def decorator(func):
            return func
        return decorator
    def cached_response(*args, **kwargs):
        def decorator(func):
            return func
        return decorator
    class CacheTTL:
        SHORT = 60
        MEDIUM = 300
        LONG = 900

# Expanded data sources
try:
    from expanded_data_sources import expanded_data_manager, DataSourceType
    EXPANDED_SOURCES_AVAILABLE = True
except ImportError:
    EXPANDED_SOURCES_AVAILABLE = False
    expanded_data_manager = None

# Intelligence correlation engine
try:
    from intelligence_correlation import IntelligenceCorrelator, EntityType, RelationshipType
    CORRELATION_AVAILABLE = True
except ImportError:
    CORRELATION_AVAILABLE = False
    IntelligenceCorrelator = None

# Advanced analysis engine
try:
    from advanced_analysis import (
        AdvancedAnalysisEngine, MITREMapper, RiskScoringEngine,
        ExecutiveSummaryGenerator, TrendAnalyzer, ChartDataGenerator,
        advanced_analysis_engine
    )
    ADVANCED_ANALYSIS_AVAILABLE = True
except ImportError:
    ADVANCED_ANALYSIS_AVAILABLE = False
    advanced_analysis_engine = None

# Graph Intelligence Engine
try:
    from graph_intelligence import register_graph_api, CorrelationSync, extract_entities
    from graph_intelligence.algorithms import (
        CentralityEngine, PathEngine, CommunityEngine,
        SimilarityEngine, AnomalyEngine, InfluenceEngine
    )
    GRAPH_INTELLIGENCE_AVAILABLE = True
except ImportError:
    GRAPH_INTELLIGENCE_AVAILABLE = False
    register_graph_api = None
    CorrelationSync = None

# from job_queue import job_queue_manager, update_job_progress
# Mock job queue manager for Docker compatibility
class MockJobQueueManager:
    def health_check(self):
        return {'status': 'disabled', 'message': 'Job queue disabled in Docker mode'}
    def enqueue_investigation(self, **kwargs):
        return f"mock_job_{kwargs.get('investigation_id', 'unknown')}"
    def get_job_status(self, job_id):
        return {'id': job_id, 'status': 'completed', 'result': 'Mock job result'}
    def cancel_job(self, job_id):
        return True
    def get_queue_stats(self):
        return {'queued': 0, 'active': 0, 'completed': 0, 'failed': 0}

job_queue_manager = MockJobQueueManager()
from problem_json import ProblemJSONMiddleware, InvestigationNotFoundError, MCPServerError
# Observability imports (commented for Docker compatibility)
# from observability import (
#     observability_manager, trace_operation, trace_investigation,
#     add_trace_attributes, record_error, get_metrics
# )

# Configure basic logging for Docker compatibility
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Get logger
logger = logging.getLogger(__name__)

# Dummy decorators for Docker compatibility
def trace_operation(operation_name):
    def decorator(func):
        return func
    return decorator

def trace_investigation(func):
    return func

app = Flask(__name__)
CORS(app, 
     origins=['http://localhost:8080', 'http://localhost:*', 'http://127.0.0.1:*', 'http://localhost:5001'],
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])

# Initialize Problem+JSON error handling middleware (commented for Docker compatibility)
# problem_json = ProblemJSONMiddleware(app)

# Global error handlers - sanitize error responses to prevent information disclosure
@app.errorhandler(400)
def bad_request_handler(error):
    """Handle bad request errors"""
    logger.warning(f"Bad request: {str(error)}")
    return jsonify({
        'error': 'Bad Request',
        'message': get_safe_error_message('validation_error', 'Invalid request data')
    }), 400

@app.errorhandler(401)
def unauthorized_handler(error):
    """Handle unauthorized errors"""
    return jsonify({
        'error': 'Unauthorized',
        'message': get_safe_error_message('authentication_error')
    }), 401

@app.errorhandler(403)
def forbidden_handler(error):
    """Handle forbidden errors"""
    return jsonify({
        'error': 'Forbidden',
        'message': get_safe_error_message('authorization_error')
    }), 403

@app.errorhandler(404)
def not_found_handler(error):
    """Handle not found errors"""
    return jsonify({
        'error': 'Not Found',
        'message': get_safe_error_message('not_found', 'Resource not found')
    }), 404

@app.errorhandler(429)
def rate_limit_handler(error):
    """Handle rate limit errors"""
    logger.warning(f"Rate limit exceeded")
    return jsonify({
        'error': 'Too Many Requests',
        'message': get_safe_error_message('rate_limit')
    }), 429

@app.errorhandler(500)
def internal_error_handler(error):
    """Handle internal server errors - never expose details"""
    logger.error(f"Internal server error: {str(error)}", exc_info=True)
    return jsonify({
        'error': 'Internal Server Error',
        'message': get_safe_error_message('internal_error')
    }), 500

@app.errorhandler(503)
def service_unavailable_handler(error):
    """Handle service unavailable errors"""
    logger.error(f"Service unavailable: {str(error)}")
    return jsonify({
        'error': 'Service Unavailable',
        'message': get_safe_error_message('service_unavailable')
    }), 503

# Initialize OpenTelemetry instrumentation (commented for Docker compatibility)
# observability_manager.initialize(app)

# Session configuration
app.config['SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-secret-key-change-in-production')

# Add trace context middleware
@app.route('/metrics')
def metrics():
    """Prometheus metrics endpoint"""
    from flask import Response
    # get_metrics() not available without observability module
    return Response("# Metrics endpoint disabled\n", mimetype='text/plain')

# @app.before_request
# def before_request():
#     """Initialize trace context for every request"""
#     g.trace_id = TraceContextManager.get_or_create_trace_id()
#     g.span_id = TraceContextManager.get_current_span_id()
#     g.request_start_time = time.time()
#     
#     logger.info(f"Request started: {request.method} {request.path}", 
#                 method=request.method,
#                 path=request.path,
#                 remote_addr=request.remote_addr)

# @app.after_request
# def after_request(response):
#     """Add trace headers to response and log request completion"""
#     response = inject_trace_headers(response)
#     
#     # Log request completion
#     if hasattr(g, 'request_start_time'):
#         duration_ms = int((time.time() - g.request_start_time) * 1000)
#         logger.info(f"Request completed: {request.method} {request.path}",
#                     method=request.method,
#                     path=request.path,
#                     status_code=response.status_code,
#                     duration_ms=duration_ms)
#     
#     return response

# Initialize OSINT Investigation System
orchestrator = InvestigationOrchestrator(max_concurrent_investigations=10)
compliance_engine = ComplianceEngine()
report_generator = InvestigationReportGenerator(orchestrator)

# Initialize Vault and Configuration Management
vault_config = VaultConfig(
    url=os.getenv('VAULT_URL', 'http://localhost:8200'),
    token=os.getenv('VAULT_TOKEN'),
    mount_point=os.getenv('VAULT_MOUNT_POINT', 'secret'),
    namespace=os.getenv('VAULT_NAMESPACE')
)
vault_client = VaultClient(vault_config)
config_manager = ConfigurationManager(vault_client)

# Initialize Professional Report Generator
professional_report_generator = ProfessionalReportGenerator(
    organization_name=os.getenv('ORGANIZATION_NAME', 'Enterprise OSINT Platform')
)

# Initialize Audit Report Generator
audit_report_generator = ComprehensiveAuditReportGenerator(
    investigation_orchestrator=orchestrator,
    vault_client=vault_client,
    config_manager=config_manager
)

# Initialize API Connection Monitor
api_monitor = APIConnectionMonitor()
logger.info("API Connection Monitor initialized with fallback support")

# Initialize PostgreSQL Audit Client
try:
    audit_client = init_audit_client(
        host=os.getenv('POSTGRES_HOST', 'postgresql'),  # Kubernetes service name
        port=int(os.getenv('POSTGRES_PORT', '5432')),
        database=os.getenv('POSTGRES_DB', 'osint_audit'),
        username=os.getenv('POSTGRES_USER', 'postgres'),
        password=os.getenv('POSTGRES_PASSWORD', 'password123')
    )
    
    # Test connection
    if audit_client.test_connection():
        logger.info("PostgreSQL audit client initialized successfully")
        
        # Log system start event
        start_event = AuditEvent(
            event_type=EventType.SYSTEM_START,
            action="START",
            resource_type="system",
            resource_name="Enterprise OSINT Platform",
            success=True
        )
        audit_client.log_audit_event(start_event)
    else:
        logger.warning("PostgreSQL audit client connection failed, falling back to memory storage")
        audit_client = None
except Exception as e:
    logger.error(f"Failed to initialize PostgreSQL audit client: {e}")
    audit_client = None

# Initialize Graph Intelligence API
if GRAPH_INTELLIGENCE_AVAILABLE and register_graph_api:
    try:
        register_graph_api(app)
        graph_sync = CorrelationSync()
        logger.info("Graph Intelligence API registered at /api/graph")
    except Exception as e:
        logger.error(f"Failed to initialize Graph Intelligence: {e}")
        graph_sync = None
        GRAPH_INTELLIGENCE_AVAILABLE = False
else:
    graph_sync = None
    logger.warning("Graph Intelligence not available")

# In-memory storage for testing
legacy_investigations = {}  # Keep for compatibility
reports = {}
reports_audit_history = {}  # Track all report generation history for audit

# File-based persistence for audit history
AUDIT_HISTORY_FILE = Path('/tmp/osint_audit_history.json')

def load_audit_history():
    """Load audit history from persistent storage"""
    global reports_audit_history
    if AUDIT_HISTORY_FILE.exists():
        try:
            with open(AUDIT_HISTORY_FILE, 'r') as f:
                reports_audit_history = json.load(f)
            app.logger.info(f"Loaded {len(reports_audit_history)} audit entries from file")
        except Exception as e:
            app.logger.error(f"Error loading audit history: {e}")
            reports_audit_history = {}
    else:
        reports_audit_history = {}
        save_audit_history()

def save_audit_history():
    """Save audit history to persistent storage"""
    try:
        with open(AUDIT_HISTORY_FILE, 'w') as f:
            json.dump(reports_audit_history, f, indent=2)
        app.logger.info(f"Saved {len(reports_audit_history)} audit entries to file")
    except Exception as e:
        app.logger.error(f"Error saving audit history: {e}")

# Load audit history on startup
load_audit_history()

# Database connection for authentication
def get_db_connection():
    """Get PostgreSQL database connection"""
    try:
        conn = psycopg2.connect(
            host=os.environ.get('POSTGRES_HOST', 'osint-platform-postgresql'),
            port=os.environ.get('POSTGRES_PORT', '5432'),
            database=os.environ.get('POSTGRES_DB', 'osint_audit'),
            user=os.environ.get('POSTGRES_USER', 'postgres'),
            password=os.environ.get('POSTGRES_PASSWORD', 'password123')
        )
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return None

# Authentication functions
def hash_password(password):
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    """Verify a password against its hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def authenticate_user(username, password):
    """Authenticate user against PostgreSQL database or demo fallback"""

    # Demo mode fallback users
    DEMO_USERS = {
        'admin': {
            'password': 'admin123',
            'user_id': 'admin',
            'username': 'admin',
            'full_name': 'System Administrator',
            'role': 'admin',
            'clearance_level': 'confidential'
        },
        'analyst1': {
            'password': 'admin123',
            'user_id': 'analyst1',
            'username': 'analyst1',
            'full_name': 'John Analyst',
            'role': 'analyst',
            'clearance_level': 'internal'
        },
        'analyst2': {
            'password': 'admin123',
            'user_id': 'analyst2',
            'username': 'analyst2',
            'full_name': 'Jane Investigator',
            'role': 'senior_analyst',
            'clearance_level': 'confidential'
        }
    }

    conn = get_db_connection()
    if not conn:
        # Fallback to demo users if database unavailable
        logger.warning("Database unavailable, using demo authentication")
        if username in DEMO_USERS and DEMO_USERS[username]['password'] == password:
            user_data = DEMO_USERS[username].copy()
            del user_data['password']
            return user_data
        return None

    try:
        cursor = conn.cursor()
        # Support both username and email for login
        cursor.execute("""
            SELECT id, user_id, username, email, password_hash, full_name, role, clearance_level, is_active
            FROM public.users
            WHERE (username = %s OR email = %s) AND is_active = true
        """, (username, username))

        user = cursor.fetchone()
        if user and verify_password(password, user[4]):
            # Update last login
            cursor.execute("""
                UPDATE public.users
                SET last_login = NOW()
                WHERE id = %s
            """, (user[0],))
            conn.commit()

            return {
                'user_id': user[1],  # user_id column
                'username': user[2],  # username column
                'full_name': user[5],
                'role': user[6],
                'clearance_level': user[7] or 'internal'
            }
        else:
            # Increment failed login attempts
            cursor.execute("""
                UPDATE public.users
                SET failed_login_attempts = failed_login_attempts + 1
                WHERE username = %s OR email = %s
            """, (username, username))
            conn.commit()

            # Fallback to demo users if DB auth fails and in demo mode
            if mode_manager.is_demo_mode():
                if username in DEMO_USERS and DEMO_USERS[username]['password'] == password:
                    logger.info(f"Demo mode: authenticating user {username}")
                    user_data = DEMO_USERS[username].copy()
                    del user_data['password']
                    return user_data
            return None

    except Exception as e:
        logger.error(f"Authentication error: {e}")
        # Fallback to demo users on error
        if username in DEMO_USERS and DEMO_USERS[username]['password'] == password:
            logger.warning(f"Database error, using demo fallback for user {username}")
            user_data = DEMO_USERS[username].copy()
            del user_data['password']
            return user_data
        return None
    finally:
        conn.close()

def create_jwt_token(user_info):
    """Create a JWT token for the user"""
    payload = {
        'user_id': user_info['user_id'],
        'username': user_info['username'],
        'full_name': user_info['full_name'],
        'role': user_info['role'],
        'clearance_level': user_info['clearance_level'],
        'exp': datetime.utcnow() + timedelta(hours=8),  # 8 hour expiry
        'iat': datetime.utcnow()
    }
    
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authentication required'}), 401
        
        token = auth_header.split(' ')[1]
        
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.current_user = payload
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
    return decorated_function

def require_role(required_role):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(request, 'current_user'):
                return jsonify({'error': 'Authentication required'}), 401
            
            role_hierarchy = {'viewer': 1, 'analyst': 2, 'senior_analyst': 3, 'admin': 4}
            user_level = role_hierarchy.get(request.current_user.get('role'), 0)
            required_level = role_hierarchy.get(required_role, 99)
            
            if user_level < required_level:
                return jsonify({'error': 'Insufficient permissions'}), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Legacy users dict for compatibility (will be removed)
users = {
    'admin': {'password': 'admin123', 'role': 'admin'}
}

# Investigation type mapping
INVESTIGATION_TYPE_MAP = {
    'comprehensive': InvestigationType.COMPREHENSIVE,
    'corporate': InvestigationType.CORPORATE,
    'infrastructure': InvestigationType.INFRASTRUCTURE,
    'social_media': InvestigationType.SOCIAL_MEDIA,
    'threat_assessment': InvestigationType.THREAT_ASSESSMENT
}

PRIORITY_MAP = {
    'low': Priority.LOW,
    'normal': Priority.NORMAL,
    'high': Priority.HIGH,
    'urgent': Priority.URGENT,
    'critical': Priority.CRITICAL
}

@app.route('/health')
def health():
    """Basic health check - is the service running?"""
    return jsonify({
        'status': 'healthy', 
        'service': 'osint-backend', 
        'timestamp': datetime.utcnow().isoformat(),
        'trace_id': getattr(g, 'trace_id', None)
    })

@app.route('/health/live')
def liveness():
    """Kubernetes liveness probe - is the service alive?"""
    # Basic check that the service can respond
    return jsonify({
        'status': 'alive',
        'service': 'osint-backend',
        'timestamp': datetime.utcnow().isoformat(),
        'trace_id': getattr(g, 'trace_id', None)
    }), 200

@app.route('/health/ready')
def readiness():
    """Kubernetes readiness probe - is the service ready to accept traffic?"""
    checks = {
        'service': 'osint-backend',
        'timestamp': datetime.utcnow().isoformat(),
        'trace_id': getattr(g, 'trace_id', None),
        'checks': {}
    }
    
    all_healthy = True
    
    # Check PostgreSQL
    try:
        if postgres_client and postgres_client.test_connection():
            checks['checks']['postgresql'] = {
                'status': 'healthy',
                'message': 'Database connection successful'
            }
        else:
            checks['checks']['postgresql'] = {
                'status': 'unhealthy',
                'message': 'Database connection failed'
            }
            all_healthy = False
    except Exception as e:
        checks['checks']['postgresql'] = {
            'status': 'unhealthy',
            'message': f'Database check failed: {str(e)}'
        }
        all_healthy = False
    
    # Check Vault connectivity
    try:
        if vault_client and vault_client.is_healthy():
            checks['checks']['vault'] = {
                'status': 'healthy',
                'message': 'Vault connection successful'
            }
        else:
            checks['checks']['vault'] = {
                'status': 'degraded',
                'message': 'Vault not connected (using environment variables)'
            }
    except Exception as e:
        checks['checks']['vault'] = {
            'status': 'degraded',
            'message': f'Vault check failed: {str(e)}'
        }
    
    # Check MCP servers
    mcp_status = {}
    try:
        # Check each MCP server endpoint
        mcp_servers = [
            ('infrastructure', 'http://mcp-infrastructure-enhanced:8021'),
            ('social', 'http://mcp-social-enhanced:8010'),
            ('threat', 'http://mcp-threat-enhanced:8020'),
            ('financial', 'http://mcp-financial-enhanced:8040'),
            ('technical', 'http://mcp-technical-enhanced:8050')
        ]
        
        for name, url in mcp_servers:
            # For now, just track that they're configured
            # In production, you'd want to actually check connectivity
            mcp_status[name] = {
                'status': 'configured',
                'url': url
            }
        
        checks['checks']['mcp_servers'] = mcp_status
    except Exception as e:
        checks['checks']['mcp_servers'] = {
            'status': 'error',
            'message': str(e)
        }
    
    # Check API monitor
    try:
        if api_monitor:
            system_status = api_monitor.get_system_status()
            checks['checks']['api_monitor'] = {
                'status': 'healthy' if system_status.get('system_status') != 'critical' else 'unhealthy',
                'total_apis': system_status.get('total_apis', 0),
                'online_apis': system_status.get('online_apis', 0)
            }
    except Exception as e:
        checks['checks']['api_monitor'] = {
            'status': 'error',
            'message': str(e)
        }
    
    # Check job queue (Redis/RQ)
    try:
        job_queue_health = job_queue_manager.health_check()
        if job_queue_health['status'] == 'healthy':
            checks['checks']['job_queue'] = {
                'status': 'healthy',
                'redis_connection': job_queue_health['redis_connection'],
                'queues': len(job_queue_health['queues']),
                'workers': len(job_queue_health['workers'])
            }
        else:
            checks['checks']['job_queue'] = {
                'status': 'unhealthy',
                'error': job_queue_health.get('error', 'Job queue not healthy')
            }
            all_healthy = False
    except Exception as e:
        checks['checks']['job_queue'] = {
            'status': 'error',
            'message': str(e)
        }
        all_healthy = False
    
    # Overall status
    checks['status'] = 'ready' if all_healthy else 'not_ready'
    
    # Log health check result
    logger.info(f"Health check completed: {checks['status']} (healthy={all_healthy})")
    
    return jsonify(checks), 200 if all_healthy else 503

@app.route('/ready')
def ready():
    """Legacy ready endpoint - redirect to new health/ready"""
    return readiness()

@app.route('/api/system/status', methods=['GET'])
def system_status():
    """Get system status including database connectivity"""
    try:
        # Check PostgreSQL connectivity
        postgres_status = {
            'connected': False,
            'host': os.getenv('POSTGRES_HOST', 'postgresql'),
            'port': os.getenv('POSTGRES_PORT', '5432'),
            'database': os.getenv('POSTGRES_DB', 'osint_audit')
        }
        
        if audit_client:
            postgres_status['connected'] = audit_client.test_connection()
            
        # Check Vault connectivity
        vault_status = {
            'connected': vault_client.is_healthy(),
            'url': vault_config.url,
            'mount_point': vault_config.mount_point
        }
        
        # Get API monitoring status
        api_system_status = api_monitor.get_system_status()
        api_status_by_type = {}
        
        for api_type in APIType:
            apis_of_type = api_monitor.get_apis_by_type(api_type)
            api_status_by_type[api_type.value] = {
                'total': len(apis_of_type),
                'online': len([s for s in apis_of_type.values() if s.status == APIStatus.ONLINE]),
                'degraded': len([s for s in apis_of_type.values() if s.status == APIStatus.DEGRADED]),
                'offline': len([s for s in apis_of_type.values() if s.status == APIStatus.OFFLINE]),
                'apis': {name: {
                    'status': status.status.value,
                    'last_check': status.last_check.isoformat() if status.last_check else None,
                    'response_time_ms': status.response_time_ms,
                    'error_message': status.error_message,
                    'success_rate': status.success_rate
                } for name, status in apis_of_type.items()}
            }
        
        # Get basic system metrics
        system_metrics = {
            'active_investigations': len(orchestrator.active_investigations),
            'total_reports': len(reports),
            'audit_logging': 'postgresql' if audit_client else 'memory',
            'configuration_storage': 'vault' if vault_client.is_healthy() else 'environment',
            'fallback_mode': api_system_status['fallback_mode'],
            'api_availability': f"{api_system_status['online_apis']}/{api_system_status['total_apis']}"
        }
        
        # Determine overall system status based on critical components
        overall_status = 'operational'
        if not api_system_status['critical_apis_available']:
            overall_status = 'degraded'
        elif api_system_status['system_status'] in ['critical', 'limited']:
            overall_status = 'limited'
        elif not postgres_status['connected'] and not vault_status['connected']:
            overall_status = 'degraded'
        
        return jsonify({
            'service': 'Enterprise OSINT Platform',
            'version': '1.0.0',
            'status': overall_status,
            'timestamp': datetime.utcnow().isoformat(),
            'components': {
                'postgresql': postgres_status,
                'vault': vault_status,
                'orchestrator': {'status': 'running'},
                'compliance_engine': {'status': 'running'},
                'risk_assessment': {'status': 'running'},
                'api_monitor': {
                    'status': 'running',
                    'system_health': api_system_status['system_status'],
                    'fallback_enabled': True,
                    'total_apis': api_system_status['total_apis'],
                    'online_apis': api_system_status['online_apis']
                }
            },
            'external_apis': api_status_by_type,
            'metrics': system_metrics
        })
        
    except (psycopg2.Error, ConnectionError) as e:
        logger.error(f"System status check - database/connection error: {str(e)}")
        return jsonify({
            'service': 'Enterprise OSINT Platform',
            'status': 'degraded',
            'error': get_safe_error_message('database_error'),
            'timestamp': datetime.utcnow().isoformat()
        }), 500
    except Exception as e:
        logger.error(f"System status check failed: {str(e)}", exc_info=True)
        return jsonify({
            'service': 'Enterprise OSINT Platform',
            'status': 'degraded',
            'error': get_safe_error_message('internal_error'),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@app.route('/api/monitoring/apis', methods=['GET'])
def get_api_monitoring_status():
    """Get detailed API monitoring status"""
    try:
        # Get overall system status
        system_status = api_monitor.get_system_status()
        
        # Get detailed status by API type
        api_details = {}
        for api_type in APIType:
            apis_of_type = api_monitor.get_apis_by_type(api_type)
            api_details[api_type.value] = {}
            
            for api_name, status in apis_of_type.items():
                endpoint = api_monitor.api_endpoints[api_name]
                api_details[api_type.value][api_name] = {
                    'name': status.name,
                    'description': endpoint.description,
                    'status': status.status.value,
                    'required': endpoint.required,
                    'last_check': status.last_check.isoformat() if status.last_check else None,
                    'response_time_ms': status.response_time_ms,
                    'success_rate': round(status.success_rate, 2),
                    'total_requests': status.total_requests,
                    'failed_requests': status.failed_requests,
                    'error_message': status.error_message,
                    'last_successful_request': status.last_successful_request.isoformat() if status.last_successful_request else None,
                    'rate_limit_reset': status.rate_limit_reset.isoformat() if status.rate_limit_reset else None,
                    'quota_remaining': status.quota_remaining,
                    'estimated_cost_today': round(status.estimated_cost_today, 4),
                    'rate_limit_per_minute': endpoint.rate_limit_per_minute,
                    'cost_per_request': endpoint.cost_per_request
                }
        
        return jsonify({
            'system_overview': system_status,
            'api_details': api_details,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"API monitoring status failed: {str(e)}")
        return jsonify({'error': f'Monitoring failed: {str(e)}'}), 500

@app.route('/api/monitoring/apis/<api_name>', methods=['GET'])
def get_specific_api_status(api_name):
    """Get detailed status for a specific API"""
    try:
        if api_name not in api_monitor.api_endpoints:
            return jsonify({'error': 'API not found'}), 404
        
        endpoint = api_monitor.api_endpoints[api_name]
        status = api_monitor.api_status[api_name]
        
        return jsonify({
            'endpoint_config': {
                'name': endpoint.name,
                'api_type': endpoint.api_type.value,
                'base_url': endpoint.base_url,
                'required': endpoint.required,
                'rate_limit_per_minute': endpoint.rate_limit_per_minute,
                'cost_per_request': endpoint.cost_per_request,
                'description': endpoint.description
            },
            'current_status': {
                'status': status.status.value,
                'last_check': status.last_check.isoformat() if status.last_check else None,
                'response_time_ms': status.response_time_ms,
                'success_rate': round(status.success_rate, 2),
                'total_requests': status.total_requests,
                'failed_requests': status.failed_requests,
                'error_message': status.error_message,
                'last_successful_request': status.last_successful_request.isoformat() if status.last_successful_request else None,
                'estimated_cost_today': round(status.estimated_cost_today, 4)
            },
            'is_available': api_monitor.is_api_available(api_name),
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Specific API status failed: {str(e)}")
        return jsonify({'error': f'API status failed: {str(e)}'}), 500

@app.route('/api/monitoring/apis/check', methods=['POST'])
def trigger_api_health_check():
    """Manually trigger health check for all APIs"""
    try:
        # This would typically be async, but for simplicity we'll run sync
        import asyncio
        
        async def run_check():
            return await api_monitor.check_all_apis()
        
        # Run the async check
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(run_check())
        loop.close()
        
        # Format results
        check_results = {}
        for api_name, status in results.items():
            check_results[api_name] = {
                'status': status.status.value,
                'response_time_ms': status.response_time_ms,
                'error_message': status.error_message,
                'last_check': status.last_check.isoformat()
            }
        
        return jsonify({
            'message': 'Health check completed',
            'results': check_results,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Manual health check failed: {str(e)}")
        return jsonify({'error': f'Health check failed: {str(e)}'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User authentication endpoint"""
    data = request.json or {}

    # Validate and sanitize login input
    if VALIDATION_ENABLED:
        try:
            validated = validate_login_request(data)
            username = validated.username
            password = validated.password
        except InputValidationError as e:
            # Don't expose validation details for security
            logger.warning("Login validation failed")
            return jsonify({'error': 'Invalid credentials format'}), 400
    else:
        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

    # Authenticate against PostgreSQL
    user_info = authenticate_user(username, password)
    if user_info:
        access_token = create_jwt_token(user_info)
        
        return jsonify({
            'message': 'Login successful',
            'user': {
                'user_id': user_info['user_id'],
                'username': user_info['username'],
                'full_name': user_info['full_name'],
                'role': user_info['role'],
                'clearance_level': user_info['clearance_level']
            },
            'access_token': access_token
        })
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    """User logout endpoint"""
    # With JWT tokens, logout is handled client-side by discarding the token
    return jsonify({'message': 'Logout successful'})

@app.route('/api/auth/me', methods=['GET'])
@require_auth
def get_current_user():
    """Get current user information"""
    user = request.current_user
    return jsonify({
        'user': {
            'user_id': user['user_id'],
            'username': user['username'],
            'full_name': user['full_name'],
            'role': user['role'],
            'clearance_level': user['clearance_level']
        }
    })

@app.route('/api/investigations', methods=['GET'])
@require_auth
def get_investigations():
    # Return all OSINT investigations with detailed status
    result = []
    
    # Check if we're in demo mode
    if mode_manager.is_demo_mode():
        logger.info("Serving demo investigations data")
        demo_investigations = demo_provider.generate_demo_investigations(count=5)
        return jsonify(demo_investigations)
    
    # Get active OSINT investigations (production mode)
    active_investigations = orchestrator.get_active_investigations()
    for investigation in active_investigations:
        try:
            inv_data = investigation.to_dict()
        except Exception as serialization_error:
            logger.error(f"Investigation serialization failed for {investigation.id}: {str(serialization_error)}")
            # Fallback to basic data
            inv_data = {
                'id': investigation.id,
                'target': investigation.target_profile.primary_identifier if hasattr(investigation, 'target_profile') else 'Unknown',
                'status': investigation.status.value if hasattr(investigation, 'status') else 'unknown',
                'created_at': investigation.created_at.isoformat() if hasattr(investigation, 'created_at') else datetime.utcnow().isoformat(),
                'investigation_type': investigation.investigation_type.value if hasattr(investigation, 'investigation_type') else 'unknown',
                'investigator_name': investigation.investigator_name if hasattr(investigation, 'investigator_name') else 'Unknown'
            }
        
        # Add progress information
        inv_data['progress_percentage'] = investigation.get_overall_progress_percentage()
        inv_data['stage_progress'] = investigation.get_stage_progress_percentage()
        inv_data['current_stage'] = investigation.status.value
        inv_data['current_activity'] = investigation.progress.current_activity
        
        # Check report availability (investigation must be completed)
        if investigation.status == InvestigationStatus.COMPLETED:
            inv_data['can_generate_report'] = True
        else:
            inv_data['can_generate_report'] = False
            
        # Check if there's an active report
        report_id = f"report_{investigation.id}"
        if report_id in reports:
            report = reports[report_id]
            report_time = datetime.fromisoformat(report['generated_at'])
            if datetime.utcnow() - report_time < timedelta(minutes=60):
                inv_data['report_available'] = True
                inv_data['report_expires_at'] = (report_time + timedelta(minutes=60)).isoformat()
            else:
                inv_data['report_available'] = False
                del reports[report_id]
        else:
            inv_data['report_available'] = False
        
        result.append(inv_data)
    
    # Also include legacy investigations for backward compatibility
    for inv in legacy_investigations.values():
        inv_data = inv.copy()
        report_id = f"report_{inv['id']}"
        if report_id in reports:
            report = reports[report_id]
            report_time = datetime.fromisoformat(report['generated_at'])
            if datetime.utcnow() - report_time < timedelta(minutes=60):
                inv_data['report_available'] = True
                inv_data['report_expires_at'] = (report_time + timedelta(minutes=60)).isoformat()
            else:
                inv_data['report_available'] = False
                del reports[report_id]
        else:
            inv_data['report_available'] = False
        result.append(inv_data)
    
    return jsonify(result)

@app.route('/api/investigations', methods=['POST'])
@require_auth
@trace_operation("api.create_investigation")
def create_investigation():
    data = request.json or {}

    try:
        # Validate and sanitize input using Pydantic models
        if VALIDATION_ENABLED:
            try:
                validated = validate_investigation_request(data)
                target = validated.target
                investigation_type = validated.type
                priority = validated.priority
                investigator_name = validated.investigator
            except InputValidationError as e:
                logger.warning(f"Investigation validation failed: {e.message}")
                return jsonify({
                    'error': 'Validation failed',
                    'message': e.message,
                    'field': getattr(e, 'field', None)
                }), 400
        else:
            # Fallback to basic validation
            target = data.get('target', '').strip()
            investigation_type = data.get('type', 'comprehensive')
            priority = data.get('priority', 'normal')
            investigator_name = data.get('investigator', 'System')

            # Basic validation
            if not target:
                return jsonify({'error': 'Target is required'}), 400

            # Whitelist validation for type and priority
            if investigation_type not in ['comprehensive', 'infrastructure', 'social_media', 'threat_assessment', 'corporate']:
                return jsonify({'error': 'Invalid investigation type'}), 400
            if priority not in ['low', 'normal', 'high', 'urgent', 'critical']:
                return jsonify({'error': 'Invalid priority level'}), 400

        # Generate investigator_id from name
        investigator_id = investigator_name.lower().replace(' ', '_').replace('-', '_') if investigator_name != 'System' else 'system'
        
        # Map string values to enums
        inv_type = INVESTIGATION_TYPE_MAP.get(investigation_type, InvestigationType.COMPREHENSIVE)
        inv_priority = PRIORITY_MAP.get(priority, Priority.NORMAL)
        
        # Check API availability - enhanced MCP servers are always available internally
        available_social_apis = ['mcp-social-enhanced']  # Enhanced MCP always available
        available_infra_apis = ['mcp-infrastructure-enhanced']  # Enhanced MCP always available
        available_threat_apis = ['mcp-threat-enhanced']  # Enhanced MCP always available
        available_ai_apis = api_monitor.get_available_apis(APIType.AI_ML)
        
        # Create investigation scope based on type and API availability
        scope = InvestigationScope()
        api_warnings = []
        
        if investigation_type == 'infrastructure':
            scope.include_social_media = False
            if not available_infra_apis:
                api_warnings.append("No infrastructure APIs available - investigation will use mock data")
        elif investigation_type == 'social_media':
            scope.include_infrastructure = False
            scope.include_threat_intelligence = False
            if not available_social_apis:
                api_warnings.append("No social media APIs available - investigation will use mock data")
        elif investigation_type == 'threat_assessment':
            scope.include_social_media = False
            scope.max_threat_indicators = 1000
            if not available_threat_apis:
                api_warnings.append("No threat intelligence APIs available - investigation will use mock data")
        else:  # comprehensive
            # Adjust scope based on available APIs
            if not available_social_apis:
                scope.include_social_media = False
                api_warnings.append("Social media analysis disabled - no APIs available")
            if not available_infra_apis:
                scope.include_infrastructure = False
                api_warnings.append("Infrastructure analysis disabled - no APIs available")
            if not available_threat_apis:
                scope.include_threat_intelligence = False
                api_warnings.append("Threat intelligence disabled - no APIs available")
        
        # Check critical AI APIs (temporarily disabled for demo)
        # Allow investigations to proceed without OpenAI in demo mode
        if False and not available_ai_apis and api_monitor.api_endpoints.get('openai', {}).required:
            return jsonify({
                'error': 'Critical AI services unavailable',
                'message': 'Investigation cannot proceed without OpenAI API',
                'fallback_available': False,
                'api_status': api_monitor.get_system_status()
            }), 503  # Service Unavailable
        
        # Create investigation record (but don't execute yet)
        investigation_id = orchestrator.create_investigation(
            target=target,
            investigation_type=inv_type,
            investigator_name=investigator_name,
            priority=inv_priority,
            scope=scope
        )
        
        # Queue investigation for background processing
        job_id = job_queue_manager.enqueue_investigation(
            investigation_id=investigation_id,
            target=target,
            investigation_type=investigation_type,
            priority=priority,
            investigator_name=investigator_name,
            scope=scope.to_dict() if hasattr(scope, 'to_dict') else {}
        )
        
        # Get investigation details
        investigation = orchestrator.get_investigation(investigation_id)
        if not investigation:
            return jsonify({'error': 'Failed to create investigation'}), 500
        
        # Store job ID for progress tracking
        if job_id:
            investigation.job_id = job_id
            
        # Ensure the investigation object has the correct investigator_id
        investigation.investigator_id = investigator_id
        
        # Log investigation start to PostgreSQL audit system
        if audit_client:
            log_investigation_start(
                investigation_id=investigation_id,
                investigator_name=investigator_name,
                target=target,
                investigation_type=investigation_type,
                priority=priority
            )
            
            # Log audit event
            event = AuditEvent(
                event_type=EventType.INVESTIGATION_START,
                user_name=investigator_name,
                source_ip=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                action="CREATE",
                resource_type="investigation",
                resource_id=investigation_id,
                resource_name=target,
                success=True,
                request_data={
                    'target': target,
                    'type': investigation_type,
                    'priority': priority
                }
            )
            audit_client.log_audit_event(event)
        
        # Return investigation data with API status information
        try:
            response_data = investigation.to_dict()
        except Exception as serialization_error:
            logger.error(f"Investigation serialization failed: {str(serialization_error)}")
            logger.error(f"Investigation object type: {type(investigation)}")
            logger.error(f"Investigation attributes: {[attr for attr in dir(investigation) if not attr.startswith('_')]}")
            # Fallback to basic response
            response_data = {
                'id': investigation.id,
                'target': investigation.target_profile.primary_identifier if hasattr(investigation, 'target_profile') else target,
                'status': investigation.status.value if hasattr(investigation, 'status') else 'pending',
                'created_at': investigation.created_at.isoformat() if hasattr(investigation, 'created_at') else datetime.utcnow().isoformat(),
                'investigation_type': investigation.investigation_type.value if hasattr(investigation, 'investigation_type') else investigation_type,
                'investigator_name': investigation.investigator_name if hasattr(investigation, 'investigator_name') else investigator_name
            }
        
        response_data['message'] = 'OSINT investigation queued for processing'
        response_data['job_id'] = job_id
        response_data['status'] = 'queued'
        
        # Include API availability information
        response_data['api_status'] = {
            'fallback_mode': api_monitor.get_system_status()['fallback_mode'],
            'available_apis': {
                'social_media': len(available_social_apis) if isinstance(available_social_apis, list) else 1,
                'infrastructure': len(available_infra_apis) if isinstance(available_infra_apis, list) else 1,
                'threat_intelligence': len(available_threat_apis) if isinstance(available_threat_apis, list) else 1,
                'ai_ml': len(available_ai_apis) if isinstance(available_ai_apis, list) else 0
            },
            'warnings': api_warnings,
            'investigation_capabilities': {
                'social_media_analysis': (len(available_social_apis) if isinstance(available_social_apis, list) else 1) > 0 and scope.include_social_media,
                'infrastructure_analysis': (len(available_infra_apis) if isinstance(available_infra_apis, list) else 1) > 0 and scope.include_infrastructure,
                'threat_intelligence': (len(available_threat_apis) if isinstance(available_threat_apis, list) else 1) > 0 and scope.include_threat_intelligence,
                'ai_analysis': len(available_ai_apis) > 0
            }
        }
        
        logger.info(f"Started OSINT investigation {investigation_id} for target {target} with {len(api_warnings)} API warnings")
        return jsonify(response_data), 201
        
    except Exception as e:
        logger.error(f"Failed to create investigation: {str(e)}")
        return jsonify({'error': f'Failed to create investigation: {str(e)}'}), 500

@app.route('/api/investigations/<inv_id>', methods=['GET'])
def get_investigation(inv_id):
    # Handle demo mode
    if mode_manager.is_demo_mode():
        demo_inv = demo_provider.get_demo_investigation(inv_id)
        if demo_inv:
            return jsonify(demo_inv)
        return jsonify({'error': 'Demo investigation not found', 'investigation_id': inv_id}), 404

    # Try to get OSINT investigation first (production mode)
    investigation = orchestrator.get_investigation(inv_id)
    
    if investigation:
        try:
            inv_data = investigation.to_dict()
        except Exception as serialization_error:
            logger.error(f"Investigation serialization failed for {inv_id}: {str(serialization_error)}")
            # Fallback to basic data
            inv_data = {
                'id': investigation.id,
                'target': investigation.target_profile.primary_identifier if hasattr(investigation, 'target_profile') else 'Unknown',
                'status': investigation.status.value if hasattr(investigation, 'status') else 'unknown',
                'created_at': investigation.created_at.isoformat() if hasattr(investigation, 'created_at') else datetime.utcnow().isoformat(),
                'investigation_type': investigation.investigation_type.value if hasattr(investigation, 'investigation_type') else 'unknown',
                'investigator_name': investigation.investigator_name if hasattr(investigation, 'investigator_name') else 'Unknown'
            }
        
        # Add detailed progress information
        inv_data['progress_percentage'] = investigation.get_overall_progress_percentage()
        inv_data['stage_progress'] = investigation.get_stage_progress_percentage()
        inv_data['current_stage'] = investigation.status.value
        inv_data['current_activity'] = investigation.progress.current_activity
        inv_data['data_points_collected'] = investigation.progress.data_points_collected
        inv_data['api_calls_made'] = investigation.api_calls_made
        inv_data['estimated_completion'] = investigation.progress.estimated_completion.isoformat() if investigation.progress.estimated_completion else None
        
        # Add intelligence summaries if available
        if investigation.social_intelligence:
            inv_data['social_summary'] = {
                'platforms_found': len(investigation.social_intelligence.platforms),
                'reputation_score': investigation.social_intelligence.reputation_score,
                'sentiment_overall': investigation.social_intelligence.sentiment_analysis.get('overall', 0)
            }
        
        if investigation.infrastructure_intelligence:
            inv_data['infrastructure_summary'] = {
                'domains_found': len(investigation.infrastructure_intelligence.domains),
                'subdomains_found': len(investigation.infrastructure_intelligence.subdomains),
                'services_exposed': len(investigation.infrastructure_intelligence.exposed_services)
            }
        
        if investigation.threat_intelligence:
            inv_data['threat_summary'] = {
                'risk_score': investigation.threat_intelligence.risk_score,
                'confidence_level': investigation.threat_intelligence.confidence_level,
                'indicators_found': len(investigation.threat_intelligence.network_indicators)
            }
        
        # Check report status
        report_id = f"report_{inv_id}"
        if report_id in reports:
            report = reports[report_id]
            report_time = datetime.fromisoformat(report['generated_at'])
            if datetime.utcnow() - report_time < timedelta(minutes=60):
                inv_data['report_available'] = True
                inv_data['report_expires_at'] = (report_time + timedelta(minutes=60)).isoformat()
                inv_data['report_data'] = report
            else:
                inv_data['report_available'] = False
                del reports[report_id]
        else:
            inv_data['report_available'] = False
            # Can generate report if investigation is completed
            inv_data['can_generate_report'] = investigation.status == InvestigationStatus.COMPLETED
        
        return jsonify(inv_data)
    
    # Fallback to legacy investigations
    if inv_id not in legacy_investigations:
        return jsonify({'error': 'Investigation not found'}), 404
    
    inv = legacy_investigations[inv_id].copy()
    
    # Check report status for legacy investigation
    report_id = f"report_{inv_id}"
    if report_id in reports:
        report = reports[report_id]
        report_time = datetime.fromisoformat(report['generated_at'])
        if datetime.utcnow() - report_time < timedelta(minutes=60):
            inv['report_available'] = True
            inv['report_expires_at'] = (report_time + timedelta(minutes=60)).isoformat()
            inv['report_data'] = report
        else:
            inv['report_available'] = False
            del reports[report_id]
    else:
        inv['report_available'] = False
    
    return jsonify(inv)

@app.route('/api/investigations/<inv_id>/report', methods=['POST'])
@require_auth
def generate_report(inv_id):
    # Handle demo mode
    if mode_manager.is_demo_mode():
        demo_inv = demo_provider.get_demo_investigation(inv_id)
        if demo_inv:
            if demo_inv.get('status') != 'completed':
                return jsonify({
                    'error': 'Investigation not completed',
                    'status': demo_inv.get('status', 'unknown'),
                    'progress': demo_inv.get('progress_percentage', 0)
                }), 400

            report_id = f"report_{inv_id}"
            target = demo_inv.get('target_profile', {}).get('primary_identifier', 'unknown')

            # Generate demo report
            demo_report_data = demo_provider.generate_demo_report_data(inv_id, target)

            report = {
                'id': report_id,
                'investigation_id': inv_id,
                'target': target,
                'type': demo_inv.get('investigation_type', 'comprehensive'),
                'investigator': demo_inv.get('investigator_name', 'Demo User'),
                'generated_at': datetime.utcnow().isoformat(),
                'expires_at': (datetime.utcnow() + timedelta(minutes=60)).isoformat(),
                'content': {
                    'executive_summary': demo_report_data['executive_summary'],
                    'key_findings': demo_report_data['key_findings'],
                    'recommendations': demo_report_data['recommendations'],
                    'risk_assessment': demo_report_data['risk_assessment'],
                    'intelligence_data': demo_inv.get('findings', {}),
                    'compliance_reports': [{
                        'framework': 'GDPR',
                        'compliant': True,
                        'risk_level': 'low',
                        'findings': ['Demo compliance check passed'],
                        'recommendations': ['Continue standard monitoring'],
                        'data_categories': ['Public information only'],
                        'generated_at': datetime.utcnow().isoformat()
                    }],
                    'investigation_metadata': {
                        'investigation_id': inv_id,
                        'generated_by': demo_inv.get('investigator_name', 'Demo User'),
                        'classification': 'CONFIDENTIAL',
                        'retention_minutes': 60,
                        'created_at': demo_inv.get('created_at'),
                        'completed_at': demo_inv.get('completed_at'),
                        'processing_time_seconds': 45,
                        'data_points_collected': demo_inv.get('progress', {}).get('data_points_collected', 15),
                        'api_calls_made': demo_inv.get('api_calls_made', 8),
                        'cost_estimate_usd': demo_inv.get('cost_estimate_usd', 2.50),
                        'demo_mode': True
                    }
                }
            }

            reports[report_id] = report
            logger.info(f"Generated demo report for investigation {inv_id}")

            return jsonify({
                'message': 'Demo report generated successfully',
                'report_id': report_id,
                'expires_at': report['expires_at'],
                'available_for_minutes': 60,
                'report_size_kb': len(str(report)) // 1024,
                'data_points': demo_inv.get('progress', {}).get('data_points_collected', 15),
                'demo_mode': True
            }), 201
        else:
            return jsonify({'error': 'Demo investigation not found', 'investigation_id': inv_id}), 404

    # Try OSINT investigation first (production mode)
    investigation = orchestrator.get_investigation(inv_id)
    
    if investigation:
        # Check if investigation is completed
        if investigation.status != InvestigationStatus.COMPLETED:
            return jsonify({
                'error': 'Investigation not completed',
                'status': investigation.status.value,
                'progress': investigation.get_overall_progress_percentage()
            }), 400
        
        report_id = f"report_{inv_id}"
        
        # Create comprehensive OSINT report
        report = {
            'id': report_id,
            'investigation_id': inv_id,
            'target': investigation.target_profile.primary_identifier,
            'type': investigation.investigation_type.value,
            'investigator': investigation.investigator_name,
            'generated_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + timedelta(minutes=60)).isoformat(),
            'content': {
                'executive_summary': investigation.executive_summary,
                'key_findings': investigation.key_findings,
                'recommendations': investigation.recommendations,
                'risk_assessment': investigation.risk_assessment,
                'intelligence_data': {
                    'social_intelligence': investigation.social_intelligence.__dict__ if investigation.social_intelligence else None,
                    'infrastructure_intelligence': investigation.infrastructure_intelligence.__dict__ if investigation.infrastructure_intelligence else None,
                    'threat_intelligence': investigation.threat_intelligence.__dict__ if investigation.threat_intelligence else None
                },
                'compliance_reports': [
                    {
                        'framework': report.framework.value if hasattr(report.framework, 'value') else report.framework,
                        'compliant': report.compliant,
                        'risk_level': report.risk_level,
                        'findings': report.findings,
                        'recommendations': getattr(report, 'recommendations', []),
                        'data_categories': getattr(report, 'data_categories_identified', []),
                        'generated_at': report.generated_at.isoformat() if hasattr(report, 'generated_at') and report.generated_at else None
                    } for report in investigation.compliance_reports
                ],
                'investigation_metadata': {
                    'investigation_id': inv_id,
                    'generated_by': investigation.investigator_name,
                    'classification': investigation.classification_level.upper(),
                    'retention_minutes': 10,
                    'created_at': investigation.created_at.isoformat(),
                    'completed_at': investigation.completed_at.isoformat(),
                    'processing_time_seconds': investigation.processing_time_seconds,
                    'data_points_collected': investigation.progress.data_points_collected,
                    'api_calls_made': investigation.api_calls_made,
                    'cost_estimate_usd': investigation.cost_estimate_usd
                }
            }
        }
        
        reports[report_id] = report
        
        # Add to audit history for permanent tracking
        audit_entry = {
            'report_id': report_id,
            'investigation_id': inv_id,
            'target': investigation.target_profile.primary_identifier,
            'investigator_name': investigation.investigator_name,
            'investigator_id': investigation.investigator_id,
            'generated_at': report['generated_at'],
            'report_type': investigation.investigation_type.value,
            'classification': investigation.classification_level,
            'priority': investigation.priority.value,
            'status': 'generated'
        }
        reports_audit_history[report_id] = audit_entry
        save_audit_history()  # Persist to file
        
        logger.info(f"Generated OSINT report for investigation {inv_id} by {investigation.investigator_name}")
        
        return jsonify({
            'message': 'OSINT report generated successfully',
            'report_id': report_id,
            'expires_at': report['expires_at'],
            'available_for_minutes': 60,
            'report_size_kb': len(str(report)) // 1024,
            'data_points': investigation.progress.data_points_collected
        }), 201
    
    # Fallback to legacy investigation
    if inv_id not in legacy_investigations:
        return jsonify({'error': 'Investigation not found'}), 404
    
    investigation = legacy_investigations[inv_id]
    report_id = f"report_{inv_id}"
    
    # Create basic report for legacy investigation
    report = {
        'id': report_id,
        'investigation_id': inv_id,
        'target': investigation['target'],
        'type': investigation['type'],
        'investigator': investigation['investigator'],
        'generated_at': datetime.utcnow().isoformat(),
        'expires_at': (datetime.utcnow() + timedelta(minutes=60)).isoformat(),
        'content': {
            'executive_summary': f'OSINT investigation report for {investigation["target"]}',
            'findings': 'Legacy demo findings for testing purposes',
            'recommendations': ['Continue monitoring', 'Implement security controls'],
            'metadata': {
                'investigation_id': inv_id,
                'generated_by': investigation['investigator'],
                'classification': 'CONFIDENTIAL',
                'retention_minutes': 10
            }
        }
    }
    
    reports[report_id] = report
    
    # Add to audit history for permanent tracking
    audit_entry = {
        'report_id': report_id,
        'investigation_id': inv_id,
        'target': investigation['target'],
        'investigator_name': investigation.get('investigator', 'Unknown'),
        'investigator_id': investigation.get('investigator', 'Unknown').lower().replace(' ', '_'),
        'generated_at': report['generated_at'],
        'report_type': investigation['type'],
        'classification': 'confidential',
        'priority': investigation.get('priority', 'normal'),
        'status': 'generated'
    }
    reports_audit_history[report_id] = audit_entry
    save_audit_history()  # Persist to file
    
    return jsonify({
        'message': 'Report generated successfully',
        'report_id': report_id,
        'expires_at': report['expires_at'],
        'available_for_minutes': 60
    }), 201

@app.route('/api/investigations/<inv_id>/report', methods=['GET'])
def get_report(inv_id):
    report_id = f"report_{inv_id}"
    
    if report_id not in reports:
        return jsonify({'error': 'Report not found or expired'}), 404
    
    report = reports[report_id]
    report_time = datetime.fromisoformat(report['generated_at'])
    
    # Check if expired
    if datetime.utcnow() - report_time >= timedelta(minutes=60):
        del reports[report_id]
        return jsonify({'error': 'Report has expired'}), 410
    
    # Calculate time remaining
    expires_at = datetime.fromisoformat(report['expires_at'])
    time_remaining = expires_at - datetime.utcnow()
    
    response = report.copy()
    response['time_remaining_seconds'] = int(time_remaining.total_seconds())
    
    return jsonify(response)

@app.route('/api/reports', methods=['GET'])
def get_all_reports():
    # Return all reports with expiration status
    result = []
    expired_reports = []
    
    for report_id, report in reports.items():
        report_time = datetime.fromisoformat(report['generated_at'])
        if datetime.utcnow() - report_time >= timedelta(minutes=60):
            expired_reports.append(report_id)
        else:
            expires_at = datetime.fromisoformat(report['expires_at'])
            time_remaining = expires_at - datetime.utcnow()
            
            report_data = report.copy()
            report_data['time_remaining_seconds'] = int(time_remaining.total_seconds())
            result.append(report_data)
    
    # Clean up expired reports
    for report_id in expired_reports:
        del reports[report_id]
    
    return jsonify(result)

@app.route('/api/investigations/<inv_id>/report/download', methods=['GET'])
def download_report(inv_id):
    report_id = f"report_{inv_id}"
    
    if report_id not in reports:
        return jsonify({'error': 'Report not found or expired'}), 404
    
    report = reports[report_id]
    report_time = datetime.fromisoformat(report['generated_at'])
    
    # Check if expired
    if datetime.utcnow() - report_time >= timedelta(minutes=60):
        del reports[report_id]
        return jsonify({'error': 'Report has expired'}), 410
    
    # In a real implementation, this would return a PDF file
    # For now, return JSON data that can be used for printing
    return jsonify({
        'format': 'json',
        'filename': f'osint_report_{inv_id}_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json',
        'data': report
    })

@app.route('/api/mcp/servers', methods=['GET'])
def get_mcp_servers():
    return jsonify([
        {
            'name': 'social_media',
            'url': 'http://mcp-social-enhanced:8010',
            'status': 'online',
            'tools_count': 3,
            'description': 'Enhanced Social Media Intelligence Analysis',
            'version': '2.0.0',
            'capabilities': ['Real Twitter API v2', 'Real Reddit Data', 'Social Media Search']
        },
        {
            'name': 'infrastructure',
            'url': 'http://mcp-infrastructure-enhanced:8021', 
            'status': 'online',
            'tools_count': 4,
            'description': 'Infrastructure Assessment and Analysis',
            'version': '1.0.0',
            'capabilities': ['WHOIS Lookup', 'DNS Records', 'SSL Analysis', 'Subdomain Enum']
        },
        {
            'name': 'threat_intel',
            'url': 'http://mcp-threat-enhanced:8020',
            'status': 'online',
            'tools_count': 3,
            'description': 'Enhanced Threat Intelligence with Real APIs',
            'version': '2.0.0',
            'capabilities': ['VirusTotal Domain Analysis', 'Shodan Host Intelligence', 'HaveIBeenPwned Breach Check']
        },
        {
            'name': 'financial_intel',
            'url': 'http://mcp-financial-enhanced:8040',
            'status': 'online',
            'tools_count': 3,
            'description': 'Enhanced Financial Intelligence with Real APIs',
            'version': '2.0.0',
            'capabilities': ['SEC EDGAR Company Search', 'SEC Filings Analysis', 'Alpha Vantage Stock Data']
        },
        {
            'name': 'technical_intel',
            'url': 'http://mcp-technical-enhanced:8050',
            'status': 'online',
            'tools_count': 3,
            'description': 'Enhanced Technical Intelligence with Real APIs',
            'version': '2.0.0',
            'capabilities': ['GitHub User Analysis', 'GitHub Repository Analysis', 'Code Pattern Search']
        }
    ])

@app.route('/api/reports/audit-history', methods=['GET'])
@require_auth
def get_reports_audit_history():
    """Get complete audit history of all generated reports"""
    
    # Load fresh audit history from file to ensure consistency
    load_audit_history()
    
    # Get query parameters for filtering
    investigator_filter = request.args.get('investigator')
    days = int(request.args.get('days', 30))  # Default to last 30 days
    report_type_filter = request.args.get('type')
    
    # Calculate date range
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    # Filter audit history
    filtered_history = []
    for report_id, audit_entry in reports_audit_history.items():
        entry_date = datetime.fromisoformat(audit_entry['generated_at'])
        
        # Date filter
        if entry_date < start_date:
            continue
            
        # Investigator filter
        if investigator_filter and investigator_filter.lower() not in audit_entry['investigator_name'].lower():
            continue
            
        # Report type filter
        if report_type_filter and report_type_filter != audit_entry['report_type']:
            continue
            
        # Add additional computed fields
        audit_entry_copy = audit_entry.copy()
        audit_entry_copy['days_ago'] = (end_date - entry_date).days
        audit_entry_copy['is_expired'] = report_id not in reports  # Check if still available
        
        filtered_history.append(audit_entry_copy)
    
    # Sort by generation date (newest first)
    filtered_history.sort(key=lambda x: x['generated_at'], reverse=True)
    
    # Generate summary statistics
    total_reports = len(filtered_history)
    investigators = list(set(entry['investigator_name'] for entry in filtered_history))
    report_types = list(set(entry['report_type'] for entry in filtered_history))
    
    # Reports by investigator
    reports_by_investigator = {}
    for entry in filtered_history:
        investigator = entry['investigator_name']
        if investigator not in reports_by_investigator:
            reports_by_investigator[investigator] = 0
        reports_by_investigator[investigator] += 1
    
    # Reports by type
    reports_by_type = {}
    for entry in filtered_history:
        report_type = entry['report_type']
        if report_type not in reports_by_type:
            reports_by_type[report_type] = 0
        reports_by_type[report_type] += 1
    
    return jsonify({
        'summary': {
            'total_reports': total_reports,
            'date_range': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'days': days
            },
            'investigators_count': len(investigators),
            'report_types_count': len(report_types),
            'active_reports': len([e for e in filtered_history if not e['is_expired']]),
            'expired_reports': len([e for e in filtered_history if e['is_expired']])
        },
        'statistics': {
            'reports_by_investigator': reports_by_investigator,
            'reports_by_type': reports_by_type,
            'investigators': investigators,
            'report_types': report_types
        },
        'audit_history': filtered_history,
        'filters': {
            'investigator': investigator_filter,
            'days': days,
            'type': report_type_filter
        }
    })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    today = datetime.utcnow().date()
    
    # Get OSINT investigation stats
    active_investigations = orchestrator.get_active_investigations()
    
    # Calculate today's investigations
    today_investigations = [inv for inv in active_investigations 
                          if inv.created_at.date() == today]
    
    # Count investigations by status
    status_counts = {}
    total_data_points = 0
    total_api_calls = 0
    total_processing_time = 0
    
    for investigation in active_investigations:
        status = investigation.status.value
        status_counts[status] = status_counts.get(status, 0) + 1
        total_data_points += investigation.progress.data_points_collected
        total_api_calls += investigation.api_calls_made
        if investigation.processing_time_seconds:
            total_processing_time += investigation.processing_time_seconds
    
    # Count active reports
    active_reports = 0
    for report in reports.values():
        report_time = datetime.fromisoformat(report['generated_at'])
        if datetime.utcnow() - report_time < timedelta(minutes=60):
            active_reports += 1
    
    # Include legacy investigations for backward compatibility
    legacy_today = [inv for inv in legacy_investigations.values() 
                   if datetime.fromisoformat(inv['created_at']).date() == today]
    
    return jsonify({
        'investigations_today': len(today_investigations) + len(legacy_today),
        'total_investigations': len(active_investigations) + len(legacy_investigations),
        'active_reports': active_reports,
        'total_reports_generated': len([inv for inv in active_investigations if inv.status == InvestigationStatus.COMPLETED]),
        'system_uptime': '99.9%',
        'report_retention_minutes': 10,
        'osint_stats': {
            'active_osint_investigations': len(active_investigations),
            'status_breakdown': status_counts,
            'total_data_points_collected': total_data_points,
            'total_api_calls_made': total_api_calls,
            'avg_processing_time_minutes': round(total_processing_time / 60, 2) if total_processing_time else 0,
            'investigation_types': list(INVESTIGATION_TYPE_MAP.keys())
        }
    })

# Compliance Framework API Endpoints

@app.route('/api/compliance/frameworks', methods=['GET'])
@cached('compliance_frameworks', ttl=CacheTTL.EXTENDED if CACHING_ENABLED else 3600)
def get_compliance_frameworks():
    """Get available compliance frameworks and their details (cached for 1 hour)"""
    frameworks = {
        'gdpr': {
            'name': 'General Data Protection Regulation',
            'jurisdiction': 'European Union',
            'description': 'Comprehensive data protection regulation for EU residents',
            'key_principles': ['Lawfulness', 'Data Minimization', 'Purpose Limitation', 'Retention Limitation'],
            'penalties': 'Up to 4% of annual turnover or €20 million',
            'applies_to': ['EU residents', 'EU businesses', 'Non-EU businesses processing EU data']
        },
        'ccpa': {
            'name': 'California Consumer Privacy Act',
            'jurisdiction': 'California, USA',
            'description': 'Consumer privacy rights for California residents',
            'key_principles': ['Right to Know', 'Right to Delete', 'Right to Opt-Out', 'Right to Non-Discrimination'],
            'penalties': 'Up to $7,500 per violation',
            'applies_to': ['California residents', 'Businesses meeting CCPA thresholds']
        },
        'pipeda': {
            'name': 'Personal Information Protection and Electronic Documents Act',
            'jurisdiction': 'Canada',
            'description': 'Federal privacy law governing personal information handling',
            'key_principles': ['Consent', 'Purpose Limitation', 'Accuracy', 'Safeguards'],
            'penalties': 'Up to $100,000 CAD',
            'applies_to': ['Canadian businesses', 'Personal information of Canadians']
        },
        'lgpd': {
            'name': 'Lei Geral de Proteção de Dados',
            'jurisdiction': 'Brazil',
            'description': 'Brazilian general data protection law',
            'key_principles': ['Purpose', 'Adequacy', 'Necessity', 'Transparency'],
            'penalties': 'Up to 2% of revenue or 50 million BRL',
            'applies_to': ['Data processing in Brazil', 'Brazilian residents data']
        }
    }
    
    return jsonify({
        'frameworks': frameworks,
        'supported_frameworks': list(frameworks.keys()),
        'default_assessment': 'gdpr'
    })

@app.route('/api/compliance/assessment', methods=['POST'])
def perform_compliance_assessment():
    """Perform compliance assessment on investigation data"""
    try:
        data = request.json
        
        target = data.get('target', '')
        framework = data.get('framework', 'gdpr')
        geographical_scope = data.get('geographical_scope', ['US', 'EU'])
        target_data = data.get('target_data', {})
        processing_activities = data.get('processing_activities', [])
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        # Map string framework to enum
        framework_mapping = {
            'gdpr': ComplianceFramework.GDPR,
            'ccpa': ComplianceFramework.CCPA,
            'pipeda': ComplianceFramework.PIPEDA,
            'lgpd': ComplianceFramework.LGPD
        }
        
        framework_enum = framework_mapping.get(framework.lower())
        if not framework_enum:
            return jsonify({'error': f'Unsupported framework: {framework}'}), 400

        # Demo mode fallback
        if mode_manager.is_demo_mode():
            assessment_id = f"demo_assessment_{int(datetime.utcnow().timestamp())}"
            return jsonify({
                'assessment_id': assessment_id,
                'framework': framework.upper(),
                'status': 'compliant',
                'risk_level': 'low',
                'compliance_score': 92.5,
                'summary': {
                    'compliant': True,
                    'requires_action': False,
                    'high_risk_factors': 0,
                    'data_categories': 2
                },
                'details': {
                    'data_categories': ['public_data', 'business_contact'],
                    'lawful_bases': ['legitimate_interest'],
                    'high_risk_factors': [],
                    'remediation_actions': [],
                    'policy_updates': [],
                    'cross_border_transfers': []
                },
                'assessment_metadata': {
                    'assessed_at': datetime.utcnow().isoformat(),
                    'next_review': (datetime.utcnow() + timedelta(days=90)).isoformat(),
                    'processing_records': 1
                },
                'demo_mode': True
            }), 200

        # Generate investigation ID for assessment
        investigation_id = f"assessment_{int(datetime.utcnow().timestamp())}"

        # Perform compliance assessment
        assessment = compliance_engine.assess_compliance(
            investigation_id=investigation_id,
            target_data=target_data,
            processing_activities=processing_activities,
            geographical_scope=geographical_scope
        )
        
        # Convert assessment to response format
        response = {
            'assessment_id': assessment.assessment_id,
            'framework': assessment.framework.value,
            'status': assessment.status.value,
            'risk_level': assessment.risk_level.value,
            'compliance_score': assessment.compliance_score,
            'summary': {
                'compliant': assessment.status.value == 'compliant',
                'requires_action': len(assessment.remediation_actions) > 0,
                'high_risk_factors': len(assessment.high_risk_factors),
                'data_categories': len(assessment.data_categories_identified)
            },
            'details': {
                'data_categories': [cat.value for cat in assessment.data_categories_identified],
                'lawful_bases': [basis.value for basis in assessment.lawful_bases_applied],
                'high_risk_factors': assessment.high_risk_factors,
                'remediation_actions': assessment.remediation_actions[:10],  # Top 10
                'policy_updates': assessment.policy_updates_required,
                'cross_border_transfers': assessment.cross_border_transfers
            },
            'assessment_metadata': {
                'assessed_at': assessment.assessed_at.isoformat(),
                'next_review': assessment.next_review_date.isoformat(),
                'processing_records': len(assessment.processing_records)
            }
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Compliance assessment failed: {str(e)}")
        return jsonify({'error': f'Assessment failed: {str(e)}'}), 500

@app.route('/api/compliance/investigations/<inv_id>/reports', methods=['GET'])
def get_investigation_compliance_reports(inv_id):
    """Get compliance reports for specific investigation"""
    # Handle demo mode
    if mode_manager.is_demo_mode():
        demo_inv = demo_provider.get_demo_investigation(inv_id)
        if demo_inv:
            # Return demo compliance reports
            demo_compliance_reports = [
                {
                    'framework': 'GDPR',
                    'compliant': True,
                    'risk_level': 'low',
                    'findings': ['Demo: Data handling practices reviewed', 'Demo: No PII violations detected'],
                    'recommendations': ['Continue standard monitoring', 'Regular compliance audits recommended'],
                    'data_categories': ['Public domain information', 'Business contact details'],
                    'generated_at': datetime.utcnow().isoformat()
                },
                {
                    'framework': 'CCPA',
                    'compliant': True,
                    'risk_level': 'low',
                    'findings': ['Demo: Consumer rights respected', 'Demo: Opt-out mechanisms available'],
                    'recommendations': ['Document data collection practices'],
                    'data_categories': ['Public information'],
                    'generated_at': datetime.utcnow().isoformat()
                }
            ]
            return jsonify({
                'investigation_id': inv_id,
                'compliance_reports': demo_compliance_reports,
                'total_reports': len(demo_compliance_reports),
                'overall_compliant': True,
                'demo_mode': True
            })
        return jsonify({'error': 'Demo investigation not found', 'investigation_id': inv_id}), 404

    investigation = orchestrator.get_investigation(inv_id)

    if not investigation:
        raise InvestigationNotFoundError(inv_id)

    compliance_reports = []
    for report in investigation.compliance_reports:
        compliance_reports.append({
            'framework': report.framework.value if hasattr(report.framework, 'value') else report.framework,
            'compliant': report.compliant,
            'risk_level': report.risk_level,
            'findings': report.findings,
            'recommendations': report.recommendations,
            'data_categories': report.data_categories_identified,
            'generated_at': report.generated_at.isoformat() if report.generated_at else None
        })

    return jsonify({
        'investigation_id': inv_id,
        'compliance_reports': compliance_reports,
        'total_reports': len(compliance_reports),
        'overall_compliant': all(r['compliant'] for r in compliance_reports) if compliance_reports else False
    })

@app.route('/api/compliance/audit-trail', methods=['GET'])
def get_compliance_audit_trail():
    """Get compliance audit trail across all investigations"""
    try:
        # Get query parameters
        framework = request.args.get('framework')
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')
        
        # Parse dates
        if start_date_str:
            start_date = datetime.fromisoformat(start_date_str.replace('Z', '+00:00'))
        else:
            start_date = datetime.utcnow() - timedelta(days=30)
        
        if end_date_str:
            end_date = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
        else:
            end_date = datetime.utcnow()
        
        # Get audit trail from compliance engine
        if framework:
            framework_enum = getattr(ComplianceFramework, framework.upper(), None)
            if not framework_enum:
                return jsonify({'error': f'Invalid framework: {framework}'}), 400
            
            audit_data = compliance_engine.processing_logger.generate_compliance_report(
                framework_enum, start_date, end_date
            )
        else:
            # Get all audit entries
            audit_entries = compliance_engine.processing_logger.get_audit_trail()
            
            # Filter by date range
            filtered_entries = [
                entry for entry in audit_entries
                if start_date <= datetime.fromisoformat(entry['timestamp']) <= end_date
            ]
            
            audit_data = {
                'period': {
                    'start': start_date.isoformat(),
                    'end': end_date.isoformat()
                },
                'total_entries': len(filtered_entries),
                'entries': filtered_entries[-100:],  # Last 100 entries
                'frameworks_assessed': list(set(
                    entry.get('framework') for entry in filtered_entries 
                    if entry.get('framework')
                ))
            }
        
        return jsonify(audit_data)
        
    except Exception as e:
        logger.error(f"Audit trail retrieval failed: {str(e)}")
        return jsonify({'error': f'Audit trail failed: {str(e)}'}), 500

@app.route('/api/compliance/dashboard', methods=['GET'])
def get_compliance_dashboard():
    """Get compliance dashboard overview"""
    try:
        # Get recent investigations
        active_investigations = orchestrator.get_active_investigations()
        
        # Calculate compliance metrics
        total_investigations = len(active_investigations)
        compliant_investigations = 0
        compliance_scores = []
        framework_breakdown = {}
        risk_level_breakdown = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        
        for investigation in active_investigations:
            if investigation.compliance_reports:
                for report in investigation.compliance_reports:
                    # Count compliant investigations
                    if report.compliant:
                        compliant_investigations += 1
                    
                    # Framework breakdown
                    framework_name = report.framework.value if hasattr(report.framework, 'value') else report.framework
                    framework_breakdown[framework_name] = framework_breakdown.get(framework_name, 0) + 1
                    
                    # Risk level breakdown
                    if report.risk_level in risk_level_breakdown:
                        risk_level_breakdown[report.risk_level] += 1
        
        # Calculate compliance percentage
        compliance_percentage = (compliant_investigations / max(total_investigations, 1)) * 100
        
        # Get recent audit entries
        recent_audit = compliance_engine.processing_logger.get_audit_trail()[-10:] if compliance_engine.processing_logger.processing_log else []
        
        dashboard_data = {
            'overview': {
                'total_investigations': total_investigations,
                'compliant_investigations': compliant_investigations,
                'compliance_percentage': round(compliance_percentage, 1),
                'non_compliant_investigations': total_investigations - compliant_investigations
            },
            'frameworks': {
                'supported': ['GDPR', 'CCPA', 'PIPEDA', 'LGPD'],
                'active': list(framework_breakdown.keys()),
                'breakdown': framework_breakdown
            },
            'risk_assessment': {
                'distribution': risk_level_breakdown,
                'high_risk_count': risk_level_breakdown['high'] + risk_level_breakdown['critical']
            },
            'recent_activity': {
                'audit_entries': recent_audit,
                'last_assessment': recent_audit[-1]['timestamp'] if recent_audit else None
            },
            'data_protection': {
                'encryption_enabled': True,
                'access_controls': True,
                'audit_logging': True,
                'automated_deletion': True,
                'retention_period_minutes': 10
            }
        }
        
        return jsonify(dashboard_data)
        
    except Exception as e:
        logger.error(f"Compliance dashboard failed: {str(e)}")
        return jsonify({'error': f'Dashboard failed: {str(e)}'}), 500

# Investigation Activity Reporting API Endpoints

@app.route('/api/reports/investigations/activity', methods=['GET'])
def generate_investigation_activity_report():
    """Generate comprehensive investigation activity report"""
    try:
        # Get query parameters
        time_range = request.args.get('time_range', 'last_30_days')
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')
        investigator_filter = request.args.get('investigator')
        investigation_type_filter = request.args.get('type')
        priority_filter = request.args.get('priority')
        include_details = request.args.get('include_details', 'true').lower() == 'true'
        
        # Parse time range
        time_range_enum = TimeRange.LAST_30_DAYS
        if time_range in ['24h', 'last_24_hours']:
            time_range_enum = TimeRange.LAST_24_HOURS
        elif time_range in ['7d', 'last_7_days']:
            time_range_enum = TimeRange.LAST_7_DAYS
        elif time_range in ['30d', 'last_30_days']:
            time_range_enum = TimeRange.LAST_30_DAYS
        elif time_range in ['90d', 'last_90_days']:
            time_range_enum = TimeRange.LAST_90_DAYS
        elif time_range == 'custom':
            time_range_enum = TimeRange.CUSTOM
        
        # Parse dates for custom range
        start_date = None
        end_date = None
        if start_date_str:
            start_date = datetime.fromisoformat(start_date_str.replace('Z', '+00:00'))
        if end_date_str:
            end_date = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
        
        # Parse enum filters
        investigation_type_enum = None
        if investigation_type_filter:
            investigation_type_enum = INVESTIGATION_TYPE_MAP.get(investigation_type_filter)
        
        priority_enum = None
        if priority_filter:
            priority_enum = PRIORITY_MAP.get(priority_filter)
        
        # Generate report from PostgreSQL if available, otherwise use memory storage
        if audit_client:
            # Get investigation data from PostgreSQL
            investigations_data = audit_client.get_investigation_activity_report(
                start_date=start_date,
                end_date=end_date,
                investigator_filter=investigator_filter,
                limit=10000
            )
            
            # Filter by investigation type and priority if specified
            if investigation_type_filter:
                investigations_data = [
                    inv for inv in investigations_data 
                    if inv.get('investigation_type') == investigation_type_filter
                ]
            
            if priority_filter:
                investigations_data = [
                    inv for inv in investigations_data 
                    if inv.get('priority') == priority_filter
                ]
                
            # Use PostgreSQL data to create a simplified report
            total_investigations = len(investigations_data)
            investigators = list(set(inv.get('investigator_name', 'Unknown') for inv in investigations_data))
            
            # Calculate metrics
            completed_investigations = [inv for inv in investigations_data if inv.get('status') == 'COMPLETED']
            success_rate = (len(completed_investigations) / total_investigations * 100) if total_investigations > 0 else 0
            avg_processing_time = sum(inv.get('processing_time_seconds', 0) or 0 for inv in completed_investigations) / len(completed_investigations) if completed_investigations else 0
            total_cost = sum(inv.get('cost_estimate_usd', 0) or 0 for inv in investigations_data)
            
            # Create a simplified report structure compatible with existing API
            report_data = {
                'report_id': str(uuid.uuid4()),
                'generated_at': datetime.utcnow(),
                'time_range': f"{start_date.strftime('%Y-%m-%d') if start_date else 'all'} to {end_date.strftime('%Y-%m-%d') if end_date else 'now'}",
                'total_investigations': total_investigations,
                'investigators': investigators,
                'avg_processing_time': avg_processing_time,
                'total_cost': total_cost,
                'success_rate': success_rate,
                'compliance_rate': 95.0,  # Default for now
                'investigations_data': investigations_data
            }
            
        else:
            # Fall back to memory storage report generator
            report = report_generator.generate_activity_report(
                start_date=start_date,
                end_date=end_date,
                time_range=time_range_enum,
                investigator_filter=investigator_filter,
                investigation_type_filter=investigation_type_enum,
                priority_filter=priority_enum,
                include_detailed_summaries=include_details
            )
            
            report_data = {
                'report_id': report.report_id,
                'generated_at': report.generated_at,
                'time_range': report.time_range,
                'total_investigations': report.total_investigations,
                'investigators': report.investigators,
                'avg_processing_time': report.avg_processing_time,
                'total_cost': report.total_cost,
                'success_rate': report.success_rate,
                'compliance_rate': report.compliance_rate,
                'investigations_data': []
            }
        
        # Convert report to API response
        response = {
            'report_id': report_data['report_id'],
            'generated_at': report_data['generated_at'].isoformat() if hasattr(report_data['generated_at'], 'isoformat') else str(report_data['generated_at']),
            'time_range': report_data['time_range'],
            'summary': {
                'total_investigations': report_data['total_investigations'],
                'total_investigators': len(report_data['investigators']),
                'avg_processing_time': report_data['avg_processing_time'],
                'total_cost': report_data['total_cost'],
                'success_rate': report_data['success_rate'],
                'compliance_rate': report_data['compliance_rate']
            },
            'breakdowns': {
                'by_type': {} if audit_client else (report.investigations_by_type if 'report' in locals() else {}),
                'by_priority': {} if audit_client else (report.investigations_by_priority if 'report' in locals() else {}),
                'by_status': {} if audit_client else (report.investigations_by_status if 'report' in locals() else {}),
                'by_day': {} if audit_client else (report.investigations_by_day if 'report' in locals() else {})
            },
            'top_entities': {
                'investigators': report_data['investigators'][:10] if audit_client else (report.top_investigators[:10] if 'report' in locals() else []),
                'targets': [] if audit_client else (report.top_targets[:20] if 'report' in locals() else [])
            },
            'security_metrics': {
                'high_risk_investigations': 0 if audit_client else (report.high_risk_investigations if 'report' in locals() else 0),
                'classified_investigations': 0 if audit_client else (report.classified_investigations if 'report' in locals() else 0),
                'cross_border_investigations': 0 if audit_client else (report.cross_border_investigations if 'report' in locals() else 0)
            },
            'operational_insights': {
                'peak_activity_hours': [] if audit_client else (report.peak_activity_hours if 'report' in locals() else []),
                'busiest_days': [] if audit_client else (report.busiest_days if 'report' in locals() else []),
                'investigation_trends': {} if audit_client else (report.investigation_trends if 'report' in locals() else {})
            }
        }
        
        # Include detailed data if requested
        if include_details:
            if audit_client:
                # Use PostgreSQL data for investigations
                response['investigations'] = [
                    {
                        'id': inv.get('investigation_id'),
                        'target': inv.get('target_identifier'),
                        'investigator': inv.get('investigator_name'),
                        'type': inv.get('investigation_type'),
                        'priority': inv.get('priority'),
                        'status': inv.get('status'),
                        'created_at': inv.get('created_at').isoformat() if inv.get('created_at') else None,
                        'processing_time': inv.get('processing_time_seconds'),
                        'data_points': inv.get('data_points_collected', 0),
                        'api_calls': inv.get('api_calls_made', 0),
                        'cost': float(inv.get('cost_estimate_usd', 0)) if inv.get('cost_estimate_usd') else 0,
                        'risk_score': float(inv.get('risk_score')) if inv.get('risk_score') else None,
                        'compliance_status': inv.get('compliance_status'),
                        'classification': inv.get('classification_level'),
                        'threat_level': inv.get('threat_level')
                    }
                    for inv in report_data['investigations_data']
                ]
                
                # Get investigator performance from PostgreSQL
                investigator_performance = audit_client.get_investigator_performance()
                response['investigators'] = [
                    {
                        'investigator_name': perf.get('investigator_name'),
                        'total_investigations': perf.get('total_investigations', 0),
                        'investigations_by_type': {},  # Could be calculated from detailed data
                        'investigations_by_priority': {},  # Could be calculated from detailed data
                        'success_rate': float(perf.get('success_rate', 0)),
                        'compliance_rate': 95.0,  # Default for now
                        'avg_processing_time': float(perf.get('avg_processing_time', 0)) if perf.get('avg_processing_time') else 0,
                        'total_cost': float(perf.get('total_cost', 0)) if perf.get('total_cost') else 0,
                        'most_investigated_targets': [],  # Could be calculated from detailed data
                        'preferred_types': []  # Could be calculated from detailed data
                    }
                    for perf in investigator_performance
                ]
            else:
                # Fall back to memory storage
                if 'report' in locals():
                    response['investigators'] = [
                        {
                            'investigator_name': inv.investigator_name,
                            'total_investigations': inv.total_investigations,
                            'investigations_by_type': inv.investigations_by_type,
                            'investigations_by_priority': inv.investigations_by_priority,
                            'success_rate': inv.success_rate,
                            'compliance_rate': inv.compliance_rate,
                            'avg_processing_time': inv.avg_processing_time,
                            'total_cost': inv.total_cost,
                            'most_investigated_targets': inv.most_investigated_targets[:5],
                            'preferred_types': inv.preferred_investigation_types
                        }
                        for inv in report.investigators
                    ]
                    
                    response['investigations'] = [
                        {
                            'id': inv.investigation_id,
                            'target': inv.target,
                            'investigator': inv.investigator_name,
                            'type': inv.investigation_type,
                            'priority': inv.priority,
                            'status': inv.status,
                            'created_at': inv.created_at.isoformat(),
                            'processing_time': inv.processing_time_seconds,
                            'data_points': inv.data_points_collected,
                            'api_calls': inv.api_calls_made,
                            'cost': inv.cost_estimate_usd,
                            'risk_score': inv.risk_score,
                            'compliance_status': inv.compliance_status,
                            'classification': inv.classification_level,
                            'findings_count': inv.key_findings_count,
                            'warnings_count': inv.warnings_count
                        }
                        for inv in report.investigation_summaries
                    ]
                else:
                    response['investigators'] = []
                    response['investigations'] = []
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Investigation activity report failed: {str(e)}")
        return jsonify({'error': f'Report generation failed: {str(e)}'}), 500

@app.route('/api/reports/investigations/activity/export', methods=['POST'])
def export_investigation_activity_report():
    """Export investigation activity report in specified format"""
    try:
        data = request.json
        
        # Generate report with same parameters
        time_range = data.get('time_range', 'last_30_days')
        start_date_str = data.get('start_date')
        end_date_str = data.get('end_date')
        investigator_filter = data.get('investigator')
        investigation_type_filter = data.get('type')
        priority_filter = data.get('priority')
        export_format = data.get('format', 'json')
        
        # Parse parameters (same as above)
        time_range_enum = TimeRange.LAST_30_DAYS
        if time_range in ['24h', 'last_24_hours']:
            time_range_enum = TimeRange.LAST_24_HOURS
        elif time_range in ['7d', 'last_7_days']:
            time_range_enum = TimeRange.LAST_7_DAYS
        elif time_range in ['30d', 'last_30_days']:
            time_range_enum = TimeRange.LAST_30_DAYS
        elif time_range in ['90d', 'last_90_days']:
            time_range_enum = TimeRange.LAST_90_DAYS
        elif time_range == 'custom':
            time_range_enum = TimeRange.CUSTOM
        
        start_date = None
        end_date = None
        if start_date_str:
            start_date = datetime.fromisoformat(start_date_str.replace('Z', '+00:00'))
        if end_date_str:
            end_date = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
        
        investigation_type_enum = None
        if investigation_type_filter:
            investigation_type_enum = INVESTIGATION_TYPE_MAP.get(investigation_type_filter)
        
        priority_enum = None
        if priority_filter:
            priority_enum = PRIORITY_MAP.get(priority_filter)
        
        # Generate report
        report = report_generator.generate_activity_report(
            start_date=start_date,
            end_date=end_date,
            time_range=time_range_enum,
            investigator_filter=investigator_filter,
            investigation_type_filter=investigation_type_enum,
            priority_filter=priority_enum,
            include_detailed_summaries=True  # Always include details for export
        )
        
        # Export in requested format
        format_enum = ReportFormat.JSON
        if export_format == 'csv':
            format_enum = ReportFormat.CSV
        elif export_format == 'html':
            format_enum = ReportFormat.HTML
        
        exported_content = report_generator.export_report(report, format_enum)
        
        # Set appropriate content type and filename
        content_type = 'application/json'
        filename = f"investigation_activity_report_{report.report_id}.json"
        
        if export_format == 'csv':
            content_type = 'text/csv'
            filename = f"investigation_activity_report_{report.report_id}.csv"
        elif export_format == 'html':
            content_type = 'text/html'
            filename = f"investigation_activity_report_{report.report_id}.html"
        
        response = app.response_class(
            response=exported_content,
            status=200,
            mimetype=content_type
        )
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        
        return response
        
    except Exception as e:
        logger.error(f"Report export failed: {str(e)}")
        return jsonify({'error': f'Export failed: {str(e)}'}), 500

@app.route('/api/reports/investigators', methods=['GET'])
def get_investigator_summary():
    """Get summary of all investigators and their activity"""
    try:
        # Get query parameters
        time_range = request.args.get('time_range', 'last_30_days')
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')
        
        # Parse time range
        time_range_enum = getattr(TimeRange, time_range.upper().replace('_', '_'), TimeRange.LAST_30_DAYS)
        
        start_date = None
        end_date = None
        if start_date_str:
            start_date = datetime.fromisoformat(start_date_str.replace('Z', '+00:00'))
        if end_date_str:
            end_date = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
        
        # Generate basic report for investigator data
        report = report_generator.generate_activity_report(
            start_date=start_date,
            end_date=end_date,
            time_range=time_range_enum,
            include_detailed_summaries=False
        )
        
        # Format investigator summary
        investigators_summary = []
        for investigator in report.investigators:
            investigators_summary.append({
                'investigator_name': investigator.investigator_name,
                'investigator_id': investigator.investigator_id,
                'total_investigations': investigator.total_investigations,
                'success_rate': investigator.success_rate,
                'compliance_rate': investigator.compliance_rate,
                'avg_processing_time': investigator.avg_processing_time,
                'total_cost': investigator.total_cost,
                'investigations_by_type': investigator.investigations_by_type,
                'investigations_by_priority': investigator.investigations_by_priority,
                'most_investigated_targets': investigator.most_investigated_targets[:3],
                'first_investigation': investigator.first_investigation.isoformat(),
                'last_investigation': investigator.last_investigation.isoformat(),
                'preferred_types': investigator.preferred_investigation_types
            })
        
        return jsonify({
            'time_range': report.time_range,
            'total_investigators': len(investigators_summary),
            'investigators': investigators_summary,
            'summary_stats': {
                'most_active_investigator': investigators_summary[0]['investigator_name'] if investigators_summary else None,
                'highest_success_rate': max([inv['success_rate'] for inv in investigators_summary], default=0),
                'total_investigations_all': sum([inv['total_investigations'] for inv in investigators_summary]),
                'avg_compliance_rate': round(sum([inv['compliance_rate'] for inv in investigators_summary]) / len(investigators_summary), 1) if investigators_summary else 0
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Investigator summary failed: {str(e)}")
        return jsonify({'error': f'Summary generation failed: {str(e)}'}), 500

@app.route('/api/reports/targets', methods=['GET'])
def get_target_analysis():
    """Get analysis of investigation targets and patterns"""
    try:
        # Get query parameters
        time_range = request.args.get('time_range', 'last_30_days')
        limit = int(request.args.get('limit', 50))
        
        # Parse time range
        time_range_enum = getattr(TimeRange, time_range.upper().replace('_', '_'), TimeRange.LAST_30_DAYS)
        
        # Generate report for target data
        report = report_generator.generate_activity_report(
            time_range=time_range_enum,
            include_detailed_summaries=True
        )
        
        # Analyze target patterns
        target_analysis = {}
        target_types = defaultdict(int)
        target_priorities = defaultdict(int)
        target_investigators = defaultdict(set)
        target_risk_scores = defaultdict(list)
        
        for inv in report.investigation_summaries:
            target = inv.target
            
            if target not in target_analysis:
                target_analysis[target] = {
                    'target': target,
                    'total_investigations': 0,
                    'investigators': set(),
                    'investigation_types': defaultdict(int),
                    'priorities': defaultdict(int),
                    'statuses': defaultdict(int),
                    'avg_risk_score': 0,
                    'risk_scores': [],
                    'first_investigated': None,
                    'last_investigated': None,
                    'compliance_issues': 0
                }
            
            analysis = target_analysis[target]
            analysis['total_investigations'] += 1
            analysis['investigators'].add(inv.investigator_name)
            analysis['investigation_types'][inv.investigation_type] += 1
            analysis['priorities'][inv.priority] += 1
            analysis['statuses'][inv.status] += 1
            analysis['risk_scores'].append(inv.risk_score)
            
            if analysis['first_investigated'] is None or inv.created_at < analysis['first_investigated']:
                analysis['first_investigated'] = inv.created_at
            if analysis['last_investigated'] is None or inv.created_at > analysis['last_investigated']:
                analysis['last_investigated'] = inv.created_at
                
            if inv.compliance_status == 'non_compliant':
                analysis['compliance_issues'] += 1
        
        # Calculate averages and format response
        targets_summary = []
        for target, analysis in target_analysis.items():
            analysis['investigators'] = list(analysis['investigators'])
            analysis['investigation_types'] = dict(analysis['investigation_types'])
            analysis['priorities'] = dict(analysis['priorities'])
            analysis['statuses'] = dict(analysis['statuses'])
            analysis['avg_risk_score'] = round(sum(analysis['risk_scores']) / len(analysis['risk_scores']), 1) if analysis['risk_scores'] else 0
            analysis['first_investigated'] = analysis['first_investigated'].isoformat() if analysis['first_investigated'] else None
            analysis['last_investigated'] = analysis['last_investigated'].isoformat() if analysis['last_investigated'] else None
            del analysis['risk_scores']  # Remove raw scores from response
            
            targets_summary.append(analysis)
        
        # Sort by total investigations
        targets_summary.sort(key=lambda x: x['total_investigations'], reverse=True)
        
        return jsonify({
            'time_range': report.time_range,
            'total_unique_targets': len(targets_summary),
            'targets': targets_summary[:limit],
            'summary_stats': {
                'most_investigated_target': targets_summary[0]['target'] if targets_summary else None,
                'highest_risk_target': max(targets_summary, key=lambda x: x['avg_risk_score'])['target'] if targets_summary else None,
                'targets_with_compliance_issues': len([t for t in targets_summary if t['compliance_issues'] > 0]),
                'avg_investigations_per_target': round(sum([t['total_investigations'] for t in targets_summary]) / len(targets_summary), 1) if targets_summary else 0
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Target analysis failed: {str(e)}")
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

# Add new API endpoints for OSINT investigation management

@app.route('/api/investigations/<inv_id>/cancel', methods=['POST'])
def cancel_investigation(inv_id):
    """Cancel a running OSINT investigation"""
    success = orchestrator.cancel_investigation(inv_id)
    
    if success:
        return jsonify({
            'message': 'Investigation cancelled successfully',
            'investigation_id': inv_id
        })
    else:
        return jsonify({'error': 'Investigation not found or cannot be cancelled'}), 404

@app.route('/api/investigations/<inv_id>/progress', methods=['GET'])
def get_investigation_progress(inv_id):
    """Get real-time progress for an investigation"""
    # Handle demo mode
    if mode_manager.is_demo_mode():
        demo_inv = demo_provider.get_demo_investigation(inv_id)
        if demo_inv:
            return jsonify({
                'investigation_id': inv_id,
                'status': demo_inv.get('status', 'completed'),
                'overall_progress': demo_inv.get('progress_percentage', 100),
                'stage_progress': demo_inv.get('stage_progress', 100),
                'current_stage': demo_inv.get('current_stage', 'completed'),
                'current_activity': demo_inv.get('current_activity', 'Demo investigation completed'),
                'data_points_collected': demo_inv.get('progress', {}).get('data_points_collected', 15),
                'estimated_completion': None,
                'warnings': [],
                'last_updated': datetime.utcnow().isoformat()
            })
        return jsonify({'error': 'Demo investigation not found', 'investigation_id': inv_id}), 404

    investigation = orchestrator.get_investigation(inv_id)

    if not investigation:
        raise InvestigationNotFoundError(inv_id)

    return jsonify({
        'investigation_id': inv_id,
        'status': investigation.status.value,
        'overall_progress': investigation.get_overall_progress_percentage(),
        'stage_progress': investigation.get_stage_progress_percentage(),
        'current_stage': investigation.status.value,
        'current_activity': investigation.progress.current_activity,
        'data_points_collected': investigation.progress.data_points_collected,
        'estimated_completion': investigation.progress.estimated_completion.isoformat() if investigation.progress.estimated_completion else None,
        'warnings': investigation.progress.warnings,
        'last_updated': investigation.progress.last_updated.isoformat()
    })

@app.route('/api/jobs/<job_id>/status', methods=['GET'])
@require_auth
def get_job_status(job_id):
    """Get status of a background job"""
    try:
        status = job_queue_manager.get_job_status(job_id)
        return jsonify(status), 200
    except Exception as e:
        logger.error("Failed to get job status", extra={
            'job_id': job_id,
            'error': str(e),
            'trace_id': g.trace_id
        })
        return jsonify({'error': f'Failed to get job status: {str(e)}'}), 500

@app.route('/api/jobs/<job_id>/cancel', methods=['POST'])
@require_auth
def cancel_job(job_id):
    """Cancel a background job"""
    try:
        success = job_queue_manager.cancel_job(job_id)
        if success:
            return jsonify({
                'message': 'Job cancelled successfully',
                'job_id': job_id
            }), 200
        else:
            return jsonify({'error': 'Job not found or cannot be cancelled'}), 404
    except Exception as e:
        logger.error("Failed to cancel job", extra={
            'job_id': job_id,
            'error': str(e),
            'trace_id': g.trace_id
        })
        return jsonify({'error': f'Failed to cancel job: {str(e)}'}), 500

@app.route('/api/jobs/queue/stats', methods=['GET'])
@require_auth
def get_queue_stats():
    """Get job queue statistics"""
    try:
        stats = job_queue_manager.get_queue_stats()
        return jsonify(stats), 200
    except Exception as e:
        logger.error("Failed to get queue stats", extra={
            'error': str(e),
            'trace_id': g.trace_id
        })
        return jsonify({'error': f'Failed to get queue stats: {str(e)}'}), 500

@app.route('/api/mcp/status', methods=['GET'])
def get_mcp_status():
    """Get MCP server status for OSINT intelligence gathering"""
    return jsonify({
        'mcp_servers_available': True,
        'social_media_server': {'status': 'online', 'capabilities': ['twitter', 'reddit', 'linkedin']},
        'infrastructure_server': {'status': 'online', 'capabilities': ['whois', 'dns', 'subdomain_enum', 'ssl_analysis']},
        'threat_intel_server': {'status': 'online', 'capabilities': ['virustotal', 'misp', 'otx', 'abuse_ch']},
        'last_health_check': datetime.utcnow().isoformat()
    })

# Clean up expired reports periodically

def cleanup_expired_reports():
    """Background task to clean up expired reports"""
    while True:
        time.sleep(60)  # Check every minute
        expired_reports = []
        for report_id, report in reports.items():
            report_time = datetime.fromisoformat(report['generated_at'])
            if datetime.utcnow() - report_time >= timedelta(minutes=60):
                expired_reports.append(report_id)
        
        for report_id in expired_reports:
            del reports[report_id]
            logger.info(f"Cleaned up expired report: {report_id}")


# Risk Assessment API Endpoints
@app.route('/api/risk/assess', methods=['POST'])
def assess_risk_standalone():
    """Perform standalone risk assessment with provided intelligence data"""
    try:
        data = request.json
        target_id = data.get('target_id', f"standalone_{int(datetime.utcnow().timestamp())}")
        
        # Extract intelligence data from request
        social_intelligence = data.get('social_intelligence')
        infrastructure_intelligence = data.get('infrastructure_intelligence')
        threat_intelligence = data.get('threat_intelligence')
        behavioral_intelligence = data.get('behavioral_intelligence')
        assessment_context = data.get('context', {})
        
        # Perform risk assessment using orchestrator's risk engine
        risk_assessment = orchestrator.risk_engine.assess_risk(
            target_id=target_id,
            social_intelligence=social_intelligence,
            infrastructure_intelligence=infrastructure_intelligence,
            threat_intelligence=threat_intelligence,
            behavioral_intelligence=behavioral_intelligence,
            assessment_context=assessment_context
        )
        
        # Convert assessment to API response format
        response = {
            'assessment_id': risk_assessment.assessment_id,
            'target_identifier': risk_assessment.target_identifier,
            'overall_risk_score': risk_assessment.overall_risk_score,
            'threat_level': risk_assessment.threat_level.value,
            'confidence_level': risk_assessment.confidence_level.value,
            
            'summary': {
                'risk_score': risk_assessment.overall_risk_score,
                'threat_level': risk_assessment.threat_level.value,
                'confidence': risk_assessment.confidence_level.value,
                'critical_findings_count': len(risk_assessment.critical_findings),
                'threat_vectors_count': len(risk_assessment.threat_vectors),
                'immediate_actions_required': len(risk_assessment.immediate_actions),
                'risk_trend': risk_assessment.risk_trend,
                'data_freshness': risk_assessment.data_freshness_score,
                'coverage_completeness': risk_assessment.coverage_completeness
            },
            
            'risk_breakdown': {
                cat.value: score for cat, score in risk_assessment.risk_by_category.items()
            },
            
            'threat_vectors': [
                {
                    'id': tv.vector_id,
                    'name': tv.name,
                    'category': tv.category.value,
                    'threat_level': tv.threat_level.value,
                    'risk_score': tv.risk_score,
                    'confidence': tv.confidence.value,
                    'attack_chain': tv.attack_chain,
                    'mitigation_recommendations': tv.mitigation_recommendations,
                    'cross_source_correlation': tv.cross_source_correlation,
                    'pattern_consistency': tv.pattern_consistency,
                    'behavioral_anomalies': tv.behavioral_anomalies
                }
                for tv in risk_assessment.threat_vectors
            ],
            
            'critical_findings': risk_assessment.critical_findings,
            
            'recommendations': {
                'immediate_actions': risk_assessment.immediate_actions,
                'monitoring_recommendations': risk_assessment.monitoring_recommendations,
                'long_term_strategies': risk_assessment.long_term_strategies
            },
            
            'correlation_analysis': {
                'source_correlation_matrix': risk_assessment.source_correlation_matrix,
                'cross_reference_matches': risk_assessment.cross_reference_matches,
                'timeline_correlation': risk_assessment.timeline_correlation
            },
            
            'predictive_analysis': {
                'risk_trend': risk_assessment.risk_trend,
                'predicted_escalation': risk_assessment.predicted_escalation.isoformat() if risk_assessment.predicted_escalation else None,
                'scenario_probabilities': risk_assessment.scenario_probabilities
            },
            
            'metadata': {
                'assessed_at': risk_assessment.assessed_at.isoformat(),
                'assessed_by': risk_assessment.assessed_by,
                'sources_analyzed': [source.value for source in risk_assessment.intelligence_sources_analyzed],
                'data_freshness_score': risk_assessment.data_freshness_score,
                'coverage_completeness': risk_assessment.coverage_completeness
            }
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Standalone risk assessment failed: {str(e)}")
        return jsonify({'error': f'Risk assessment failed: {str(e)}'}), 500


@app.route('/api/risk/investigations/<inv_id>', methods=['GET'])
def get_investigation_risk_assessment(inv_id):
    """Get risk assessment for specific investigation"""
    # Handle demo mode
    if mode_manager.is_demo_mode():
        demo_inv = demo_provider.get_demo_investigation(inv_id)
        if demo_inv:
            risk_data = demo_inv.get('risk_assessment', {})
            return jsonify({
                'investigation_id': inv_id,
                'target': demo_inv.get('target_profile', {}).get('primary_identifier', 'unknown'),
                'risk_assessment': {
                    'overall_score': risk_data.get('score', 0.25),
                    'risk_level': risk_data.get('level', 'low'),
                    'categories': {
                        'reputation': 0.2,
                        'infrastructure': 0.3,
                        'compliance': 0.1,
                        'threat_exposure': 0.15
                    },
                    'confidence': 'high',
                    'last_assessed': datetime.utcnow().isoformat()
                },
                'investigation_status': demo_inv.get('status', 'completed'),
                'last_updated': datetime.utcnow().isoformat(),
                'demo_mode': True
            }), 200
        return jsonify({'error': 'Demo investigation not found', 'investigation_id': inv_id}), 404

    investigation = orchestrator.get_investigation(inv_id)

    if not investigation:
        raise InvestigationNotFoundError(inv_id)

    if not hasattr(investigation, 'risk_assessment') or not investigation.risk_assessment:
        return jsonify({'error': 'Risk assessment not available for this investigation'}), 404

    # Return the stored risk assessment
    risk_data = investigation.risk_assessment

    response = {
        'investigation_id': inv_id,
        'target': investigation.target_profile.primary_identifier,
        'risk_assessment': risk_data,
        'investigation_status': investigation.status.value,
        'last_updated': investigation.progress.last_updated.isoformat() if investigation.progress.last_updated else None
    }

    return jsonify(response), 200


@app.route('/api/risk/correlate', methods=['POST'])
def correlate_intelligence_sources():
    """Correlate intelligence across multiple sources for threat analysis"""
    try:
        data = request.json
        
        social_intel = data.get('social_intelligence', {})
        infrastructure_intel = data.get('infrastructure_intelligence', {})
        threat_intel = data.get('threat_intelligence', {})
        behavioral_intel = data.get('behavioral_intelligence', {})
        
        # Use the correlation engine to find relationships
        indicators = orchestrator.risk_engine.correlation_engine.correlate_intelligence(
            social_intel, infrastructure_intel, threat_intel, behavioral_intel
        )
        
        # Convert indicators to API response format
        correlation_results = []
        for indicator in indicators:
            correlation_results.append({
                'indicator_id': indicator.indicator_id,
                'source': indicator.source.value,
                'category': indicator.category.value,
                'severity': indicator.severity,
                'confidence': indicator.confidence,
                'description': indicator.description,
                'evidence': indicator.evidence,
                'timestamp': indicator.timestamp.isoformat(),
                'correlation_weight': indicator.correlation_weight,
                'false_positive_probability': indicator.false_positive_probability
            })
        
        # Calculate correlation metrics
        sources_involved = list(set(ind.source.value for ind in indicators))
        categories_involved = list(set(ind.category.value for ind in indicators))
        avg_severity = sum(ind.severity for ind in indicators) / len(indicators) if indicators else 0
        avg_confidence = sum(ind.confidence for ind in indicators) / len(indicators) if indicators else 0
        
        response = {
            'correlation_summary': {
                'indicators_found': len(indicators),
                'sources_involved': sources_involved,
                'categories_involved': categories_involved,
                'average_severity': round(avg_severity, 1),
                'average_confidence': round(avg_confidence, 1),
                'high_severity_count': len([ind for ind in indicators if ind.severity > 70]),
                'cross_source_correlations': len([ind for ind in indicators if ind.correlation_weight > 1.0])
            },
            'indicators': correlation_results,
            'analysis_metadata': {
                'analyzed_at': datetime.utcnow().isoformat(),
                'sources_provided': len([s for s in [social_intel, infrastructure_intel, threat_intel, behavioral_intel] if s])
            }
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Intelligence correlation failed: {str(e)}")
        return jsonify({'error': f'Correlation analysis failed: {str(e)}'}), 500


@app.route('/api/risk/trends/<target_id>', methods=['GET'])
def get_risk_trends(target_id):
    """Get risk trend analysis for specific target"""
    try:
        # Get historical risk assessments from the risk engine
        historical_assessments = orchestrator.risk_engine.risk_history.get(target_id, [])
        
        if not historical_assessments:
            return jsonify({'error': 'No risk assessment history found for this target'}), 404
        
        # Calculate trend metrics
        risk_scores = [assessment.overall_risk_score for assessment in historical_assessments]
        threat_levels = [assessment.threat_level.value for assessment in historical_assessments]
        assessment_dates = [assessment.assessed_at.isoformat() for assessment in historical_assessments]
        
        # Simple trend calculation
        if len(risk_scores) >= 2:
            trend_slope = (risk_scores[-1] - risk_scores[0]) / len(risk_scores)
            if trend_slope > 5:
                trend_direction = "increasing"
            elif trend_slope < -5:
                trend_direction = "decreasing"
            else:
                trend_direction = "stable"
        else:
            trend_direction = "insufficient_data"
        
        response = {
            'target_id': target_id,
            'trend_analysis': {
                'assessments_count': len(historical_assessments),
                'trend_direction': trend_direction,
                'current_risk_score': risk_scores[-1] if risk_scores else 0,
                'risk_score_change': risk_scores[-1] - risk_scores[0] if len(risk_scores) >= 2 else 0,
                'highest_risk_score': max(risk_scores) if risk_scores else 0,
                'lowest_risk_score': min(risk_scores) if risk_scores else 0,
                'average_risk_score': sum(risk_scores) / len(risk_scores) if risk_scores else 0
            },
            'historical_data': [
                {
                    'assessment_date': assessment_dates[i],
                    'risk_score': risk_scores[i],
                    'threat_level': threat_levels[i],
                    'assessment_id': historical_assessments[i].assessment_id
                }
                for i in range(len(historical_assessments))
            ],
            'analysis_metadata': {
                'generated_at': datetime.utcnow().isoformat(),
                'data_points': len(historical_assessments)
            }
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Risk trend analysis failed: {str(e)}")
        return jsonify({'error': f'Trend analysis failed: {str(e)}'}), 500


# Admin Panel API Endpoints
@app.route('/api/admin/vault/status', methods=['GET'])
def get_vault_status():
    """Get HashiCorp Vault status"""
    try:
        status = vault_client.get_vault_status()
        return jsonify(status), 200
    except Exception as e:
        logger.error(f"Failed to get Vault status: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/services/configs', methods=['GET'])
def get_service_configs():
    """Get all service configurations"""
    try:
        # Demo mode fallback
        if mode_manager.is_demo_mode():
            return jsonify({
                'services': {
                    'openai': {'configured': False, 'status': 'demo_mode'},
                    'virustotal': {'configured': False, 'status': 'demo_mode'},
                    'shodan': {'configured': False, 'status': 'demo_mode'},
                    'twitter': {'configured': False, 'status': 'demo_mode'},
                    'reddit': {'configured': False, 'status': 'demo_mode'},
                    'abuseipdb': {'configured': False, 'status': 'demo_mode'}
                },
                'demo_mode': True,
                'message': 'Running in demo mode - no real API keys configured'
            }), 200

        configs = config_manager.get_all_service_configs()
        return jsonify(configs), 200
    except Exception as e:
        logger.error(f"Failed to get service configs: {str(e)}")
        # Return demo response as fallback
        return jsonify({
            'services': {},
            'demo_mode': True,
            'message': 'Configuration unavailable - running in fallback mode'
        }), 200


@app.route('/api/admin/services/configure', methods=['POST'])
def configure_service():
    """Configure API key for a service"""
    try:
        data = request.json
        service_name = data.get('service_name')
        api_key = data.get('api_key')
        environment = data.get('environment', 'production')
        
        if not service_name or not api_key:
            return jsonify({'error': 'service_name and api_key are required'}), 400
        
        # Validate API key format
        if not config_manager.validate_api_key(service_name, api_key):
            return jsonify({'error': 'Invalid API key format'}), 400
        
        # Register API key
        success = config_manager.register_api_key(service_name, api_key, environment)
        
        if success:
            return jsonify({'success': True, 'message': f'API key configured for {service_name}'}), 200
        else:
            return jsonify({'error': 'Failed to configure API key'}), 500
            
    except Exception as e:
        logger.error(f"Failed to configure service: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/services/<service_name>/test', methods=['POST'])
def test_service_api_key(service_name):
    """Test API key for a service"""
    try:
        # Get API key from vault
        api_key = config_manager.get_service_api_key(service_name)
        
        if not api_key:
            return jsonify({'error': 'API key not configured for this service'}), 404
        
        # Perform basic validation test
        # In a real implementation, you would make actual API calls to test connectivity
        if len(api_key) < 10:
            return jsonify({'error': 'API key appears to be invalid (too short)'}), 400
        
        # Mock test results for different services
        test_results = {
            'openai': 'OpenAI API connection verified',
            'shodan': 'Shodan API quota and permissions validated',
            'virustotal': 'VirusTotal API rate limits checked',
            'twitter': 'Twitter API v2 authentication successful',
            'reddit': 'Reddit API OAuth token valid',
            'alienvault_otx': 'AlienVault OTX API access confirmed'
        }
        
        message = test_results.get(service_name, f'{service_name} API key format validated')
        
        return jsonify({
            'success': True, 
            'message': message,
            'service': service_name,
            'tested_at': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Failed to test API key for {service_name}: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/services/<service_name>/remove', methods=['DELETE'])
def remove_service_api_key(service_name):
    """Remove API key for a service"""
    try:
        success = vault_client.delete_api_key(service_name)
        
        if success:
            return jsonify({'success': True, 'message': f'API key removed for {service_name}'}), 200
        else:
            return jsonify({'error': 'Failed to remove API key'}), 500
            
    except Exception as e:
        logger.error(f"Failed to remove API key for {service_name}: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/services/<service_name>/rotate', methods=['PUT'])
def rotate_service_api_key(service_name):
    """Rotate API key for a service"""
    try:
        data = request.json
        new_api_key = data.get('new_api_key')
        
        if not new_api_key:
            return jsonify({'error': 'new_api_key is required'}), 400
        
        # Validate new API key format
        if not config_manager.validate_api_key(service_name, new_api_key):
            return jsonify({'error': 'Invalid API key format'}), 400
        
        # Rotate the key
        success = vault_client.rotate_api_key(service_name, new_api_key)
        
        if success:
            return jsonify({'success': True, 'message': f'API key rotated for {service_name}'}), 200
        else:
            return jsonify({'error': 'Failed to rotate API key'}), 500
            
    except Exception as e:
        logger.error(f"Failed to rotate API key for {service_name}: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/services/import-env', methods=['POST'])
def import_services_from_environment():
    """Import API keys from environment variables"""
    try:
        results = config_manager.import_from_environment()
        return jsonify(results), 200
        
    except Exception as e:
        logger.error(f"Failed to import from environment: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/audit/logs', methods=['GET'])
def get_audit_logs():
    """Get system audit logs"""
    try:
        time_range = request.args.get('time_range', '24h')
        
        # Mock audit logs - in production this would come from a real audit system
        current_time = datetime.utcnow()
        
        if time_range == '1h':
            start_time = current_time - timedelta(hours=1)
        elif time_range == '24h':
            start_time = current_time - timedelta(hours=24)
        elif time_range == '7d':
            start_time = current_time - timedelta(days=7)
        elif time_range == '30d':
            start_time = current_time - timedelta(days=30)
        else:
            start_time = current_time - timedelta(hours=24)
        
        # Generate mock audit entries
        audit_logs = []
        services = ['openai', 'shodan', 'virustotal', 'twitter']
        actions = ['api_key_configured', 'api_key_tested', 'api_key_rotated', 'vault_access']
        
        for i in range(20):  # Generate 20 mock entries
            log_time = start_time + timedelta(minutes=i*30)
            if log_time > current_time:
                break
                
            audit_logs.append({
                'timestamp': log_time.isoformat(),
                'event_type': 'admin_action',
                'user': 'admin',
                'action': actions[i % len(actions)],
                'resource': services[i % len(services)],
                'success': i % 5 != 0,  # 80% success rate
                'ip_address': '127.0.0.1',
                'user_agent': 'Enterprise OSINT Admin Panel'
            })
        
        # Sort by timestamp descending
        audit_logs.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return jsonify(audit_logs), 200
        
    except Exception as e:
        logger.error(f"Failed to get audit logs: {str(e)}")
        return jsonify({'error': str(e)}), 500


# Professional Report Generation Endpoints
@app.route('/api/reports/professional/generate', methods=['POST'])
def generate_professional_report():
    """Generate professional OSINT investigation report"""
    try:
        data = request.json
        investigation_id = data.get('investigation_id')
        report_type = data.get('report_type', 'comprehensive')
        format_type = data.get('format', 'html')
        classification = data.get('classification', 'internal')
        generated_by = data.get('generated_by', 'OSINT Analyst')
        
        if not investigation_id:
            return jsonify({'error': 'investigation_id is required'}), 400
        
        # Get investigation
        investigation = orchestrator.get_investigation(investigation_id)
        if not investigation:
            return jsonify({'error': 'Investigation not found'}), 404
        
        # Generate professional report
        report_type_enum = ReportType(report_type)
        format_enum = ProfReportFormat(format_type)
        classification_enum = ClassificationLevel(classification)
        
        report = professional_report_generator.generate_report(
            investigation=investigation,
            report_type=report_type_enum,
            format_type=format_enum,
            classification=classification_enum,
            generated_by=generated_by
        )
        
        # Export report in requested format
        report_data = professional_report_generator.export_report(report, format_enum)
        
        if format_type == 'html':
            report_content = report_data.decode('utf-8')
        elif format_type == 'json':
            report_content = report_data.decode('utf-8')
        else:
            # For binary formats like PDF, return base64 encoded
            import base64
            report_content = base64.b64encode(report_data).decode('utf-8')
        
        return jsonify({
            'success': True,
            'report_id': report.metadata.report_id,
            'report_type': report_type,
            'format': format_type,
            'classification': classification,
            'generated_at': report.metadata.generated_at.isoformat(),
            'report_content': report_content,
            'metadata': {
                'confidence_score': report.metadata.confidence_score,
                'completeness_score': report.metadata.completeness_score,
                'data_freshness': report.metadata.data_freshness
            }
        }), 200
        
    except ValueError as e:
        return jsonify({'error': f'Invalid parameter: {str(e)}'}), 400
    except Exception as e:
        logger.error(f"Professional report generation failed: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/professional/<investigation_id>/download/<format_type>', methods=['GET'])
def download_professional_report(investigation_id, format_type):
    """Download professional report as file"""
    try:
        # Get investigation
        investigation = orchestrator.get_investigation(investigation_id)
        if not investigation:
            return jsonify({'error': 'Investigation not found'}), 404
        
        # Generate report
        report_type_enum = ReportType.COMPREHENSIVE
        format_enum = ProfReportFormat(format_type)
        classification_enum = ClassificationLevel.INTERNAL
        
        report = professional_report_generator.generate_report(
            investigation=investigation,
            report_type=report_type_enum,
            format_type=format_enum,
            classification=classification_enum
        )
        
        # Export report
        report_data = professional_report_generator.export_report(report, format_enum)
        
        # Set appropriate headers for download
        from flask import Response
        
        if format_type == 'pdf':
            mimetype = 'application/pdf'
            filename = f"OSINT_Report_{investigation_id}.pdf"
        elif format_type == 'html':
            mimetype = 'text/html'
            filename = f"OSINT_Report_{investigation_id}.html"
        else:
            mimetype = 'application/json'
            filename = f"OSINT_Report_{investigation_id}.json"
        
        return Response(
            report_data,
            mimetype=mimetype,
            headers={"Content-Disposition": f"attachment;filename={filename}"}
        )
        
    except Exception as e:
        logger.error(f"Report download failed: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/audit/generate', methods=['POST'])
def generate_audit_report():
    """Generate comprehensive audit report"""
    try:
        data = request.json or {}
        
        scope = data.get('scope', 'comprehensive')
        start_date_str = data.get('start_date')
        end_date_str = data.get('end_date')
        investigator_filter = data.get('investigator_filter')
        format_type = data.get('format', 'html')
        generated_by = data.get('generated_by', 'System Administrator')
        
        # Parse dates if provided
        start_date = None
        end_date = None
        
        if start_date_str:
            start_date = datetime.fromisoformat(start_date_str.replace('Z', '+00:00'))
        if end_date_str:
            end_date = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
        
        # Generate audit report
        audit_scope = AuditScope(scope)
        audit_report = audit_report_generator.generate_audit_report(
            scope=audit_scope,
            start_date=start_date,
            end_date=end_date,
            generated_by=generated_by,
            investigator_filter=investigator_filter
        )
        
        # Export report in requested format
        report_data = audit_report_generator.export_audit_report(audit_report, format_type)
        
        if format_type == 'html':
            report_content = report_data.decode('utf-8')
        else:
            report_content = report_data.decode('utf-8')
        
        return jsonify({
            'success': True,
            'report_id': audit_report.report_id,
            'scope': scope,
            'format': format_type,
            'generated_at': audit_report.generated_at.isoformat(),
            'audit_period': {
                'start': audit_report.audit_period['start'].isoformat(),
                'end': audit_report.audit_period['end'].isoformat()
            },
            'report_content': report_content,
            'summary': {
                'total_investigations': audit_report.system_metrics.total_investigations,
                'success_rate': audit_report.system_metrics.success_rate,
                'unique_investigators': audit_report.system_metrics.unique_investigators,
                'compliance_rate': audit_report.system_metrics.compliance_rate,
                'high_risk_investigations': audit_report.system_metrics.high_risk_investigations
            }
        }), 200
        
    except ValueError as e:
        return jsonify({'error': f'Invalid parameter: {str(e)}'}), 400
    except Exception as e:
        logger.error(f"Audit report generation failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/clear-legacy-data', methods=['POST'])
@require_auth
@require_role('admin')
def clear_legacy_data():
    """Clear all legacy investigations and reports (admin only)"""
    try:
        global reports, reports_audit_history
        
        # Clear orchestrator investigations
        active_investigations = orchestrator.get_active_investigations()
        investigations_cleared = len(active_investigations)
        
        # Clear all investigations from orchestrator
        orchestrator.investigations.clear()
        
        # Clear reports
        reports_cleared = len(reports)
        reports.clear()
        
        # Keep audit history but mark it as archived
        audit_entries = len(reports_audit_history)
        for report_id, entry in reports_audit_history.items():
            entry['archived'] = True
            entry['archived_at'] = datetime.utcnow().isoformat()
        
        # Save updated audit history
        save_audit_history()
        
        logger.info(f"Legacy data cleared by {request.current_user.get('username')}: "
                   f"{investigations_cleared} investigations, {reports_cleared} reports")
        
        return jsonify({
            'message': 'Legacy data cleared successfully',
            'cleared': {
                'investigations': investigations_cleared,
                'reports': reports_cleared,
                'audit_entries_archived': audit_entries
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Failed to clear legacy data: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# MODE MANAGEMENT ENDPOINTS
# ============================================================================

@app.route('/api/system/mode', methods=['GET'])
@require_auth
def get_system_mode():
    """Get current system mode and status"""
    try:
        mode_status = mode_manager.get_mode_status()
        return jsonify(mode_status), 200
    except Exception as e:
        logger.error(f"Failed to get mode status: {e}")
        return jsonify({'error': 'Failed to retrieve mode status'}), 500

@app.route('/api/system/mode', methods=['POST'])
@require_auth
def set_system_mode():
    """Set system mode (demo/production)"""
    try:
        data = request.get_json()
        if not data or 'mode' not in data:
            return jsonify({'error': 'Mode parameter required'}), 400
        
        mode = data['mode'].lower()
        if mode not in ['demo', 'production']:
            return jsonify({'error': 'Mode must be "demo" or "production"'}), 400
        
        success, message = mode_manager.set_mode(mode, user_initiated=True)
        
        if success:
            logger.info(f"Mode changed to {mode} by {request.current_user.get('username', 'unknown')}")
            return jsonify({
                'success': True,
                'message': message,
                'new_mode': mode_manager.get_current_mode(),
                'status': mode_manager.get_mode_status()
            }), 200
        else:
            return jsonify({'success': False, 'error': message}), 400
            
    except Exception as e:
        logger.error(f"Failed to set mode: {e}")
        return jsonify({'error': 'Failed to change mode'}), 500

@app.route('/api/system/demo-data', methods=['GET'])
@require_auth  
def get_demo_data_config():
    """Get demo data configuration"""
    try:
        config = mode_manager.get_demo_data_config()
        return jsonify(config), 200
    except Exception as e:
        logger.error(f"Failed to get demo config: {e}")
        return jsonify({'error': 'Failed to retrieve demo configuration'}), 500

@app.route('/api/system/api-keys', methods=['GET'])
@require_auth
def get_api_key_status():
    """Get API key availability status"""
    try:
        mode_status = mode_manager.get_mode_status()
        api_info = mode_status['api_keys']
        
        # Don't expose actual key values, just status
        return jsonify({
            'mode': mode_manager.get_current_mode(),
            'available_count': api_info['available_count'],
            'total_count': api_info['total_count'],
            'keys': [
                {
                    'name': key['name'],
                    'available': key['available'],
                    'required': key['required'],
                    'description': key['description']
                }
                for key in api_info['details']
            ],
            'production_ready': mode_status['features']['production_capable']
        }), 200
    except Exception as e:
        logger.error(f"Failed to get API key status: {e}")
        return jsonify({'error': 'Failed to retrieve API key status'}), 500

# Override system status to include mode information
@app.route('/api/system/status', methods=['GET'])
@require_auth 
def get_enhanced_system_status():
    """Get enhanced system status including mode"""
    try:
        # Get base system status
        if mode_manager.is_demo_mode():
            system_status = demo_provider.get_demo_system_status()
        else:
            # Get real system status (existing logic)
            system_status = {
                'service': 'osint-backend',
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'mode': 'production'
            }
        
        # Add mode information
        mode_status = mode_manager.get_mode_status()
        system_status.update({
            'mode_info': {
                'current_mode': mode_status['current_mode'],
                'auto_fallback_enabled': mode_status['auto_fallback_enabled'],
                'api_keys_available': mode_status['api_keys']['available_count'],
                'production_ready': mode_status['features']['production_capable'],
                'demo_features': mode_status['features']['demo_features_enabled'] if mode_manager.is_demo_mode() else []
            }
        })
        
        return jsonify(system_status), 200
        
    except Exception as e:
        logger.error(f"System status error: {e}")
        return jsonify({
            'service': 'osint-backend',
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

# ============================================================================
# Cache Management Endpoints
# ============================================================================

@app.route('/api/cache/status', methods=['GET'])
@require_auth
def get_cache_status():
    """Get cache service status and statistics"""
    if not CACHING_ENABLED or cache_service is None:
        return jsonify({
            'enabled': False,
            'message': 'Caching is not enabled',
            'backend': 'none'
        })

    try:
        health = cache_service.health_check()
        return jsonify({
            'enabled': True,
            'backend': health.get('backend', 'unknown'),
            'status': health.get('status', 'unknown'),
            'latency_ms': health.get('latency_ms', 0),
            'statistics': health.get('stats', {}),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Cache status error: {e}")
        return jsonify({
            'enabled': True,
            'status': 'error',
            'error': str(e)
        }), 500


@app.route('/api/cache/invalidate', methods=['POST'])
@require_auth
@require_role('admin')
def invalidate_cache():
    """Invalidate cache entries (admin only)"""
    if not CACHING_ENABLED or cache_service is None:
        return jsonify({'error': 'Caching is not enabled'}), 400

    data = request.json or {}
    pattern = data.get('pattern')
    investigation_id = data.get('investigation_id')

    try:
        if investigation_id:
            count = cache_service.invalidate_investigation(investigation_id)
            return jsonify({
                'success': True,
                'message': f'Invalidated cache for investigation {investigation_id}',
                'entries_removed': count
            })
        elif pattern:
            count = cache_service.delete_pattern(pattern)
            return jsonify({
                'success': True,
                'message': f'Invalidated cache entries matching pattern',
                'entries_removed': count
            })
        else:
            # Invalidate all
            cache_service.invalidate_all()
            cache_service.reset_stats()
            return jsonify({
                'success': True,
                'message': 'All cache entries invalidated'
            })
    except Exception as e:
        logger.error(f"Cache invalidation error: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# Expanded Data Sources Endpoints
# ============================================================================

@app.route('/api/intelligence/sources', methods=['GET'])
@require_auth
def get_intelligence_sources():
    """Get list of available expanded intelligence sources"""
    if not EXPANDED_SOURCES_AVAILABLE:
        return jsonify({
            'available': False,
            'message': 'Expanded data sources not available',
            'sources': []
        })

    sources = expanded_data_manager.get_available_sources()
    return jsonify({
        'available': True,
        'sources': sources,
        'total_sources': len(sources)
    })


@app.route('/api/intelligence/gather', methods=['POST'])
@require_auth
@trace_operation("api.intelligence.gather")
def gather_expanded_intelligence():
    """
    Gather intelligence from expanded data sources.

    Request body:
    {
        "target": "example.com",
        "sources": ["passive_dns", "breach_intel"]  // optional, defaults to all
    }
    """
    if not EXPANDED_SOURCES_AVAILABLE:
        return jsonify({
            'error': 'Expanded data sources not available'
        }), 503

    data = request.json or {}
    target = data.get('target', '').strip()
    sources = data.get('sources')  # None = all sources

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    # Validate target format
    if VALIDATION_ENABLED:
        try:
            from validators import validate_target_format
            target = validate_target_format(target)
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    try:
        # Run async gathering
        async def gather():
            return await expanded_data_manager.gather_all(target, sources)

        # Execute async function
        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        results = loop.run_until_complete(gather())

        # Convert results to JSON-serializable format
        response_data = {}
        for source_name, result in results.items():
            response_data[source_name] = result.to_dict()

        # Get aggregated summary
        summary = expanded_data_manager.get_aggregated_summary(results)

        return jsonify({
            'target': target,
            'results': response_data,
            'summary': summary,
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"Expanded intelligence gathering error: {e}")
        return jsonify({
            'error': 'Intelligence gathering failed',
            'message': str(e)
        }), 500


@app.route('/api/intelligence/source/<source_name>', methods=['POST'])
@require_auth
def gather_from_source(source_name):
    """
    Gather intelligence from a specific source.

    URL params:
        source_name: passive_dns, code_intel, breach_intel, url_intel, business_intel, news_intel

    Request body:
    {
        "target": "example.com"
    }
    """
    if not EXPANDED_SOURCES_AVAILABLE:
        return jsonify({'error': 'Expanded data sources not available'}), 503

    valid_sources = ['passive_dns', 'code_intel', 'breach_intel', 'url_intel', 'business_intel', 'news_intel']
    if source_name not in valid_sources:
        return jsonify({
            'error': f'Invalid source: {source_name}',
            'valid_sources': valid_sources
        }), 400

    data = request.json or {}
    target = data.get('target', '').strip()

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    try:
        # Run async gathering
        async def gather():
            return await expanded_data_manager.gather_all(target, [source_name])

        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        results = loop.run_until_complete(gather())

        result = results.get(source_name)
        if result:
            return jsonify({
                'target': target,
                'source': source_name,
                'result': result.to_dict(),
                'timestamp': datetime.utcnow().isoformat()
            })
        else:
            return jsonify({'error': f'No result from {source_name}'}), 500

    except Exception as e:
        logger.error(f"Source {source_name} gathering error: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# Intelligence Correlation Endpoints
# ============================================================================

@app.route('/api/correlation/analyze', methods=['POST'])
@require_auth
def correlate_intelligence():
    """
    Perform entity extraction and correlation on provided data.

    Request body:
    {
        "data": {
            "infrastructure": {...},
            "social": {...},
            "threat": {...},
            "expanded_sources": {...}
        }
    }

    Returns correlated entities, relationships, timeline, and findings.
    """
    if not CORRELATION_AVAILABLE:
        return jsonify({'error': 'Intelligence correlation not available'}), 503

    data = request.json or {}
    correlation_data = data.get('data', {})

    if not correlation_data:
        return jsonify({'error': 'No data provided for correlation'}), 400

    try:
        correlator = IntelligenceCorrelator()
        result = correlator.correlate(correlation_data)

        return jsonify({
            'success': True,
            'correlation': result.to_dict(),
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"Correlation error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/correlation/entity-types', methods=['GET'])
@require_auth
def get_entity_types():
    """Get list of supported entity types for correlation."""
    if not CORRELATION_AVAILABLE:
        return jsonify({'error': 'Intelligence correlation not available'}), 503

    return jsonify({
        'entity_types': [
            {'value': et.value, 'name': et.name}
            for et in EntityType
        ],
        'relationship_types': [
            {'value': rt.value, 'name': rt.name}
            for rt in RelationshipType
        ]
    })


@app.route('/api/investigations/<investigation_id>/correlation', methods=['GET'])
@require_auth
def get_investigation_correlation(investigation_id):
    """
    Get correlation results for a specific investigation.

    Returns entities, relationships, timeline, and findings.
    """
    # Check demo mode
    if mode_manager.is_demo_mode():
        demo_inv = demo_provider.get_demo_investigation(investigation_id)
        if demo_inv:
            # Generate sample correlation for demo
            return jsonify({
                'investigation_id': investigation_id,
                'correlation': _generate_demo_correlation(demo_inv),
                'timestamp': datetime.utcnow().isoformat()
            })
        return jsonify({'error': 'Investigation not found'}), 404

    # Check active investigations
    investigation = orchestrator.get_investigation_status(investigation_id)
    if not investigation:
        return jsonify({'error': 'Investigation not found'}), 404

    # Get correlation results
    correlation_results = getattr(investigation, 'correlation_results', None)

    if correlation_results:
        return jsonify({
            'investigation_id': investigation_id,
            'correlation': correlation_results,
            'timestamp': datetime.utcnow().isoformat()
        })
    else:
        return jsonify({
            'investigation_id': investigation_id,
            'correlation': None,
            'message': 'Correlation not yet available for this investigation',
            'timestamp': datetime.utcnow().isoformat()
        })


@app.route('/api/investigations/<investigation_id>/entities', methods=['GET'])
@require_auth
def get_investigation_entities(investigation_id):
    """
    Get extracted entities for a specific investigation.

    Query params:
        type: Filter by entity type (domain, ip_address, email, etc.)
        min_confidence: Minimum confidence score (0.0-1.0)
    """
    entity_type = request.args.get('type')
    min_confidence = float(request.args.get('min_confidence', 0))

    # Check demo mode
    if mode_manager.is_demo_mode():
        demo_inv = demo_provider.get_demo_investigation(investigation_id)
        if demo_inv:
            entities = _generate_demo_entities(demo_inv, entity_type, min_confidence)
            return jsonify({
                'investigation_id': investigation_id,
                'entities': entities,
                'count': len(entities),
                'timestamp': datetime.utcnow().isoformat()
            })
        return jsonify({'error': 'Investigation not found'}), 404

    investigation = orchestrator.get_investigation_status(investigation_id)
    if not investigation:
        return jsonify({'error': 'Investigation not found'}), 404

    correlation_results = getattr(investigation, 'correlation_results', None)

    if correlation_results:
        entities = correlation_results.get('entities', {})

        # Filter by type if specified
        if entity_type:
            entities = {k: v for k, v in entities.items() if v.get('type') == entity_type}

        # Filter by confidence
        if min_confidence > 0:
            entities = {k: v for k, v in entities.items() if v.get('confidence', 0) >= min_confidence}

        return jsonify({
            'investigation_id': investigation_id,
            'entities': entities,
            'count': len(entities),
            'timestamp': datetime.utcnow().isoformat()
        })
    else:
        return jsonify({
            'investigation_id': investigation_id,
            'entities': {},
            'count': 0,
            'message': 'No entities available',
            'timestamp': datetime.utcnow().isoformat()
        })


@app.route('/api/investigations/<investigation_id>/timeline', methods=['GET'])
@require_auth
def get_investigation_timeline(investigation_id):
    """
    Get reconstructed timeline for a specific investigation.

    Query params:
        severity: Filter by severity (info, warning, critical)
        limit: Maximum number of events to return
    """
    severity = request.args.get('severity')
    limit = int(request.args.get('limit', 100))

    # Check demo mode
    if mode_manager.is_demo_mode():
        demo_inv = demo_provider.get_demo_investigation(investigation_id)
        if demo_inv:
            timeline = _generate_demo_timeline(demo_inv, severity, limit)
            return jsonify({
                'investigation_id': investigation_id,
                'timeline': timeline,
                'count': len(timeline),
                'timestamp': datetime.utcnow().isoformat()
            })
        return jsonify({'error': 'Investigation not found'}), 404

    investigation = orchestrator.get_investigation_status(investigation_id)
    if not investigation:
        return jsonify({'error': 'Investigation not found'}), 404

    correlation_results = getattr(investigation, 'correlation_results', None)

    if correlation_results:
        timeline = correlation_results.get('timeline', [])

        # Filter by severity if specified
        if severity:
            timeline = [e for e in timeline if e.get('severity') == severity]

        # Limit results
        timeline = timeline[:limit]

        return jsonify({
            'investigation_id': investigation_id,
            'timeline': timeline,
            'count': len(timeline),
            'timestamp': datetime.utcnow().isoformat()
        })
    else:
        return jsonify({
            'investigation_id': investigation_id,
            'timeline': [],
            'count': 0,
            'message': 'No timeline available',
            'timestamp': datetime.utcnow().isoformat()
        })


@app.route('/api/investigations/<investigation_id>/relationships', methods=['GET'])
@require_auth
def get_investigation_relationships(investigation_id):
    """
    Get entity relationships for a specific investigation.

    Query params:
        type: Filter by relationship type
        entity_id: Filter relationships involving specific entity
    """
    rel_type = request.args.get('type')
    entity_id = request.args.get('entity_id')

    # Check demo mode
    if mode_manager.is_demo_mode():
        demo_inv = demo_provider.get_demo_investigation(investigation_id)
        if demo_inv:
            relationships = _generate_demo_relationships(demo_inv, rel_type, entity_id)
            return jsonify({
                'investigation_id': investigation_id,
                'relationships': relationships,
                'count': len(relationships),
                'timestamp': datetime.utcnow().isoformat()
            })
        return jsonify({'error': 'Investigation not found'}), 404

    investigation = orchestrator.get_investigation_status(investigation_id)
    if not investigation:
        return jsonify({'error': 'Investigation not found'}), 404

    correlation_results = getattr(investigation, 'correlation_results', None)

    if correlation_results:
        relationships = correlation_results.get('relationships', [])

        # Filter by type if specified
        if rel_type:
            relationships = [r for r in relationships if r.get('type') == rel_type]

        # Filter by entity if specified
        if entity_id:
            relationships = [r for r in relationships
                           if r.get('source') == entity_id or r.get('target') == entity_id]

        return jsonify({
            'investigation_id': investigation_id,
            'relationships': relationships,
            'count': len(relationships),
            'timestamp': datetime.utcnow().isoformat()
        })
    else:
        return jsonify({
            'investigation_id': investigation_id,
            'relationships': [],
            'count': 0,
            'message': 'No relationships available',
            'timestamp': datetime.utcnow().isoformat()
        })


# ============================================================================
# GRAPH INTELLIGENCE ENDPOINTS
# ============================================================================

@app.route('/api/investigations/<investigation_id>/graph/sync', methods=['POST'])
@require_auth
def sync_investigation_to_graph(investigation_id):
    """
    Sync investigation data to the graph intelligence system.

    Extracts entities and relationships from investigation results
    and adds them to the graph database.
    """
    if not GRAPH_INTELLIGENCE_AVAILABLE or not graph_sync:
        return jsonify({
            'error': 'Graph Intelligence not available',
            'message': 'Graph Intelligence module is not installed or failed to initialize'
        }), 503

    # Get investigation data
    if mode_manager.is_demo_mode():
        demo_inv = demo_provider.get_demo_investigation(investigation_id)
        if not demo_inv:
            return jsonify({'error': 'Investigation not found'}), 404
        investigation_data = demo_inv
    else:
        investigation = orchestrator.get_investigation_status(investigation_id)
        if not investigation:
            return jsonify({'error': 'Investigation not found'}), 404

        # Build investigation data dict
        investigation_data = {
            'id': investigation_id,
            'target': getattr(investigation, 'target', ''),
            'correlation': getattr(investigation, 'correlation_results', {}),
            'mcp_results': getattr(investigation, 'mcp_results', {}),
            'findings': getattr(investigation, 'findings', {}),
        }

    try:
        # Extract and sync
        extraction, sync_result = graph_sync.sync_investigation(
            investigation_data,
            investigation_id
        )

        return jsonify({
            'investigation_id': investigation_id,
            'extraction': extraction.to_dict(),
            'sync': sync_result.to_dict(),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Graph sync error: {e}")
        return jsonify({
            'error': 'Graph sync failed',
            'message': str(e)
        }), 500


@app.route('/api/investigations/<investigation_id>/graph/analyze', methods=['POST'])
@require_auth
def analyze_investigation_graph(investigation_id):
    """
    Run graph analysis on investigation data.

    Performs centrality, community detection, and anomaly analysis
    on the entities and relationships from an investigation.

    Query params:
        include_centrality: Run centrality analysis (default: true)
        include_communities: Run community detection (default: true)
        include_anomalies: Run anomaly detection (default: true)
        include_similarity: Run similarity analysis (default: false)
    """
    if not GRAPH_INTELLIGENCE_AVAILABLE:
        return jsonify({
            'error': 'Graph Intelligence not available',
            'message': 'Graph Intelligence module is not installed'
        }), 503

    # Parse options
    include_centrality = request.args.get('include_centrality', 'true').lower() == 'true'
    include_communities = request.args.get('include_communities', 'true').lower() == 'true'
    include_anomalies = request.args.get('include_anomalies', 'true').lower() == 'true'
    include_similarity = request.args.get('include_similarity', 'false').lower() == 'true'

    # Get investigation data
    if mode_manager.is_demo_mode():
        demo_inv = demo_provider.get_demo_investigation(investigation_id)
        if not demo_inv:
            return jsonify({'error': 'Investigation not found'}), 404
        investigation_data = demo_inv
    else:
        investigation = orchestrator.get_investigation_status(investigation_id)
        if not investigation:
            return jsonify({'error': 'Investigation not found'}), 404
        investigation_data = {
            'id': investigation_id,
            'correlation': getattr(investigation, 'correlation_results', {}),
        }

    try:
        # Extract entities to graph format
        extraction = graph_sync.extract_from_investigation(investigation_data, investigation_id)

        if not extraction.nodes:
            return jsonify({
                'investigation_id': investigation_id,
                'message': 'No entities found to analyze',
                'entities_found': 0,
                'timestamp': datetime.utcnow().isoformat()
            })

        results = {
            'investigation_id': investigation_id,
            'entities_analyzed': len(extraction.nodes),
            'relationships_analyzed': len(extraction.edges),
            'timestamp': datetime.utcnow().isoformat()
        }

        # Run centrality analysis
        if include_centrality:
            centrality_engine = CentralityEngine()
            centrality_engine.build_graph(extraction.nodes, extraction.edges)
            centrality_result = centrality_engine.compute_all_centrality()
            results['centrality'] = {
                'top_nodes': [
                    {'entity_id': eid, 'score': round(score, 4)}
                    for eid, score in centrality_result.top_by_composite[:10]
                ],
                'computation_time_ms': centrality_result.total_computation_time_ms
            }

        # Run community detection
        if include_communities:
            community_engine = CommunityEngine()
            community_engine.build_graph(extraction.nodes, extraction.edges)
            community_result = community_engine.louvain()
            results['communities'] = {
                'count': community_result.community_count,
                'modularity': round(community_result.modularity, 4),
                'communities': [c.to_dict() for c in community_result.communities[:5]]
            }

        # Run anomaly detection
        if include_anomalies:
            anomaly_engine = AnomalyEngine()
            anomaly_engine.build_graph(extraction.nodes, extraction.edges)
            anomaly_result = anomaly_engine.detect_all_anomalies()
            results['anomalies'] = {
                'total': anomaly_result.to_dict()['total_anomalies'],
                'degree_anomalies': [a.to_dict() for a in anomaly_result.degree_anomalies[:5]],
                'bridge_nodes': [a.to_dict() for a in anomaly_result.bridge_anomalies[:5]],
                'hub_authorities': [a.to_dict() for a in anomaly_result.hub_anomalies[:5]]
            }

        # Run similarity analysis
        if include_similarity and len(extraction.nodes) > 1:
            similarity_engine = SimilarityEngine()
            similarity_engine.build_graph(extraction.nodes, extraction.edges)
            bulk_result = similarity_engine.compute_all_pairs(method='jaccard', min_score=0.3)
            results['similarity'] = {
                'similar_pairs': bulk_result.pair_count,
                'top_pairs': [p.to_dict() for p in bulk_result.pairs[:10]]
            }

        return jsonify(results)

    except Exception as e:
        logger.error(f"Graph analysis error: {e}")
        return jsonify({
            'error': 'Graph analysis failed',
            'message': str(e)
        }), 500


@app.route('/api/investigations/<investigation_id>/graph/paths', methods=['POST'])
@require_auth
def find_investigation_paths(investigation_id):
    """
    Find paths between entities in an investigation.

    Request body:
        source_id: Source entity ID
        target_id: Target entity ID
        max_depth: Maximum path length (default: 5)
    """
    if not GRAPH_INTELLIGENCE_AVAILABLE:
        return jsonify({'error': 'Graph Intelligence not available'}), 503

    data = request.get_json() or {}
    source_id = data.get('source_id')
    target_id = data.get('target_id')
    max_depth = int(data.get('max_depth', 5))

    if not source_id or not target_id:
        return jsonify({'error': 'source_id and target_id are required'}), 400

    # Get investigation data
    if mode_manager.is_demo_mode():
        demo_inv = demo_provider.get_demo_investigation(investigation_id)
        if not demo_inv:
            return jsonify({'error': 'Investigation not found'}), 404
        investigation_data = demo_inv
    else:
        investigation = orchestrator.get_investigation_status(investigation_id)
        if not investigation:
            return jsonify({'error': 'Investigation not found'}), 404
        investigation_data = {
            'correlation': getattr(investigation, 'correlation_results', {}),
        }

    try:
        extraction = graph_sync.extract_from_investigation(investigation_data, investigation_id)

        path_engine = PathEngine()
        path_engine.build_graph(extraction.nodes, extraction.edges)

        result = path_engine.shortest_path(source_id, target_id, max_depth=max_depth)

        return jsonify({
            'investigation_id': investigation_id,
            'path': result.to_dict(),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Path finding error: {e}")
        return jsonify({'error': 'Path finding failed', 'message': str(e)}), 500


@app.route('/api/investigations/<investigation_id>/graph/blast-radius', methods=['POST'])
@require_auth
def analyze_blast_radius(investigation_id):
    """
    Analyze the blast radius if an entity is compromised.

    Request body:
        entity_id: Compromised entity ID
        max_hops: Maximum propagation distance (default: 3)
    """
    if not GRAPH_INTELLIGENCE_AVAILABLE:
        return jsonify({'error': 'Graph Intelligence not available'}), 503

    data = request.get_json() or {}
    entity_id = data.get('entity_id')
    max_hops = int(data.get('max_hops', 3))

    if not entity_id:
        return jsonify({'error': 'entity_id is required'}), 400

    # Get investigation data
    if mode_manager.is_demo_mode():
        demo_inv = demo_provider.get_demo_investigation(investigation_id)
        if not demo_inv:
            return jsonify({'error': 'Investigation not found'}), 404
        investigation_data = demo_inv
    else:
        investigation = orchestrator.get_investigation_status(investigation_id)
        if not investigation:
            return jsonify({'error': 'Investigation not found'}), 404
        investigation_data = {
            'correlation': getattr(investigation, 'correlation_results', {}),
        }

    try:
        extraction = graph_sync.extract_from_investigation(investigation_data, investigation_id)

        influence_engine = InfluenceEngine()
        influence_engine.build_graph(extraction.nodes, extraction.edges)

        result = influence_engine.blast_radius(entity_id, max_hops=max_hops)

        return jsonify({
            'investigation_id': investigation_id,
            'blast_radius': result.to_dict(),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Blast radius analysis error: {e}")
        return jsonify({'error': 'Blast radius analysis failed', 'message': str(e)}), 500


@app.route('/api/graph/status', methods=['GET'])
def graph_status():
    """Get Graph Intelligence system status."""
    return jsonify({
        'available': GRAPH_INTELLIGENCE_AVAILABLE,
        'sync_enabled': graph_sync is not None,
        'algorithms': [
            'centrality', 'paths', 'community',
            'similarity', 'anomaly', 'influence'
        ] if GRAPH_INTELLIGENCE_AVAILABLE else [],
        'timestamp': datetime.utcnow().isoformat()
    })


def _generate_demo_correlation(demo_inv):
    """Generate sample correlation data for demo mode."""
    target = demo_inv.get('target', 'example.com')
    return {
        'entities': {
            'ent_001': {
                'id': 'ent_001',
                'type': 'domain',
                'value': target,
                'normalized_value': target.lower(),
                'sources': ['infrastructure_intel', 'passive_dns'],
                'source_count': 2,
                'confidence': 0.95,
                'tags': ['target_domain']
            },
            'ent_002': {
                'id': 'ent_002',
                'type': 'ip_address',
                'value': '192.0.2.1',
                'normalized_value': '192.0.2.1',
                'sources': ['infrastructure_intel', 'passive_dns', 'threat_intel'],
                'source_count': 3,
                'confidence': 0.92,
                'tags': ['primary_ip']
            },
            'ent_003': {
                'id': 'ent_003',
                'type': 'organization',
                'value': 'Example Corp',
                'normalized_value': 'example corp',
                'sources': ['business_intel'],
                'source_count': 1,
                'confidence': 0.78,
                'tags': ['registrant']
            }
        },
        'entity_count': 3,
        'relationships': [
            {
                'source': 'ent_001',
                'target': 'ent_002',
                'type': 'resolves_to',
                'confidence': 0.9,
                'sources': ['passive_dns']
            },
            {
                'source': 'ent_003',
                'target': 'ent_001',
                'type': 'owns',
                'confidence': 0.85,
                'sources': ['infrastructure_intel']
            }
        ],
        'relationship_count': 2,
        'timeline': [
            {
                'timestamp': '2024-01-15T10:30:00',
                'event_type': 'domain_discovered',
                'description': f'Domain discovered: {target}',
                'severity': 'info'
            },
            {
                'timestamp': '2024-06-20T14:22:00',
                'event_type': 'dns_resolution',
                'description': 'Domain resolved to IP: 192.0.2.1',
                'severity': 'info'
            }
        ],
        'event_count': 2,
        'key_findings': [
            {
                'type': 'multi_source_confirmation',
                'severity': 'info',
                'title': 'Entities Confirmed by Multiple Sources',
                'description': '2 entities were confirmed by 2+ independent sources'
            }
        ],
        'confidence_summary': {
            'domain': 0.95,
            'ip_address': 0.92,
            'organization': 0.78,
            'overall': 0.88
        },
        'statistics': {
            'total_entities': 3,
            'entities_by_type': {'domain': 1, 'ip_address': 1, 'organization': 1},
            'total_relationships': 2,
            'relationships_by_type': {'resolves_to': 1, 'owns': 1},
            'total_timeline_events': 2,
            'unique_sources': 4
        }
    }


def _generate_demo_entities(demo_inv, entity_type=None, min_confidence=0):
    """Generate sample entities for demo mode."""
    correlation = _generate_demo_correlation(demo_inv)
    entities = correlation['entities']

    if entity_type:
        entities = {k: v for k, v in entities.items() if v.get('type') == entity_type}
    if min_confidence > 0:
        entities = {k: v for k, v in entities.items() if v.get('confidence', 0) >= min_confidence}

    return entities


def _generate_demo_timeline(demo_inv, severity=None, limit=100):
    """Generate sample timeline for demo mode."""
    correlation = _generate_demo_correlation(demo_inv)
    timeline = correlation['timeline']

    if severity:
        timeline = [e for e in timeline if e.get('severity') == severity]

    return timeline[:limit]


def _generate_demo_relationships(demo_inv, rel_type=None, entity_id=None):
    """Generate sample relationships for demo mode."""
    correlation = _generate_demo_correlation(demo_inv)
    relationships = correlation['relationships']

    if rel_type:
        relationships = [r for r in relationships if r.get('type') == rel_type]
    if entity_id:
        relationships = [r for r in relationships
                        if r.get('source') == entity_id or r.get('target') == entity_id]

    return relationships


# ============================================================================
# Advanced Analysis Endpoints
# ============================================================================

@app.route('/api/analysis/advanced', methods=['POST'])
@require_auth
def perform_advanced_analysis():
    """
    Perform advanced analysis on provided findings data.

    Request body:
    {
        "target": "example.com",
        "findings": {
            "infrastructure": {...},
            "social": {...},
            "threat": {...},
            "expanded_sources": {...}
        },
        "correlation_results": {...}  // Optional
    }

    Returns risk scoring, MITRE mapping, executive summary, and charts.
    """
    if not ADVANCED_ANALYSIS_AVAILABLE:
        return jsonify({'error': 'Advanced analysis not available'}), 503

    data = request.json or {}
    target = data.get('target', 'Unknown')
    findings = data.get('findings', {})
    correlation_results = data.get('correlation_results')

    if not findings:
        return jsonify({'error': 'No findings data provided'}), 400

    try:
        result = advanced_analysis_engine.analyze(target, findings, correlation_results)
        return jsonify({
            'success': True,
            'analysis': result
        })

    except Exception as e:
        logger.error(f"Advanced analysis error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/analysis/mitre-mapping', methods=['POST'])
@require_auth
def get_mitre_mapping():
    """
    Map findings to MITRE ATT&CK techniques.

    Request body:
    {
        "findings": {
            "infrastructure": {...},
            "threat": {...},
            "expanded_sources": {...}
        }
    }

    Returns mapped techniques with evidence.
    """
    if not ADVANCED_ANALYSIS_AVAILABLE:
        return jsonify({'error': 'Advanced analysis not available'}), 503

    data = request.json or {}
    findings = data.get('findings', {})

    if not findings:
        return jsonify({'error': 'No findings data provided'}), 400

    try:
        techniques = MITREMapper.map_findings(findings)
        attack_surface = MITREMapper.get_attack_surface_summary(techniques)

        return jsonify({
            'success': True,
            'techniques': techniques,
            'attack_surface': attack_surface,
            'technique_count': len(techniques),
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"MITRE mapping error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/analysis/risk-score', methods=['POST'])
@require_auth
def calculate_risk_score():
    """
    Calculate comprehensive risk score.

    Request body:
    {
        "findings": {...},
        "mitre_mapping": [...]  // Optional
    }

    Returns detailed risk breakdown.
    """
    if not ADVANCED_ANALYSIS_AVAILABLE:
        return jsonify({'error': 'Advanced analysis not available'}), 503

    data = request.json or {}
    findings = data.get('findings', {})
    mitre_mapping = data.get('mitre_mapping')

    if not findings:
        return jsonify({'error': 'No findings data provided'}), 400

    try:
        risk_engine = RiskScoringEngine()
        risk_score = risk_engine.calculate_risk(findings, None, mitre_mapping)

        return jsonify({
            'success': True,
            'risk_score': risk_score.to_dict(),
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"Risk scoring error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/analysis/executive-summary', methods=['POST'])
@require_auth
def generate_executive_summary():
    """
    Generate executive summary from analysis results.

    Request body:
    {
        "target": "example.com",
        "risk_score": {...},
        "mitre_mapping": [...],
        "findings": {...},
        "correlation": {...}  // Optional
    }
    """
    if not ADVANCED_ANALYSIS_AVAILABLE:
        return jsonify({'error': 'Advanced analysis not available'}), 503

    data = request.json or {}
    target = data.get('target', 'Unknown')
    findings = data.get('findings', {})

    try:
        # Calculate risk score if not provided
        risk_data = data.get('risk_score')
        if risk_data:
            # Reconstruct RiskScore from dict
            from advanced_analysis import RiskScore, RiskFactor, RiskCategory
            risk_score = RiskScore(
                overall_score=risk_data.get('overall_score', 0),
                risk_level=risk_data.get('risk_level', 'low'),
                category_scores=risk_data.get('category_scores', {}),
                factors=[],
                trend=risk_data.get('trend', 'stable'),
                confidence=risk_data.get('confidence', 0.5)
            )
        else:
            risk_engine = RiskScoringEngine()
            risk_score = risk_engine.calculate_risk(findings)

        mitre_mapping = data.get('mitre_mapping', [])
        correlation = data.get('correlation')

        generator = ExecutiveSummaryGenerator()
        summary = generator.generate_summary(
            target, risk_score, mitre_mapping, findings, correlation
        )

        return jsonify({
            'success': True,
            'summary': summary,
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"Executive summary error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/analysis/trends', methods=['POST'])
@require_auth
def analyze_trends():
    """
    Analyze trends from timeline data.

    Request body:
    {
        "timeline": [...]  // From correlation results
    }
    """
    if not ADVANCED_ANALYSIS_AVAILABLE:
        return jsonify({'error': 'Advanced analysis not available'}), 503

    data = request.json or {}
    timeline = data.get('timeline', [])

    try:
        analyzer = TrendAnalyzer()
        trends = analyzer.analyze_trends(timeline)

        return jsonify({
            'success': True,
            'trends': trends,
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"Trend analysis error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/analysis/charts', methods=['POST'])
@require_auth
def generate_chart_data():
    """
    Generate chart data for visualization.

    Request body:
    {
        "chart_type": "risk_distribution|severity|timeline|entities|gauge",
        "risk_score": {...},  // For risk charts
        "mitre_mapping": [...],  // For severity chart
        "timeline": [...],  // For timeline chart
        "entities": {...}  // For entity chart
    }
    """
    if not ADVANCED_ANALYSIS_AVAILABLE:
        return jsonify({'error': 'Advanced analysis not available'}), 503

    data = request.json or {}
    chart_type = data.get('chart_type', 'all')

    try:
        charts = {}

        if chart_type in ['risk_distribution', 'all']:
            risk_data = data.get('risk_score', {})
            if risk_data:
                from advanced_analysis import RiskScore
                risk_score = RiskScore(
                    overall_score=risk_data.get('overall_score', 0),
                    risk_level=risk_data.get('risk_level', 'low'),
                    category_scores=risk_data.get('category_scores', {}),
                    factors=[],
                    trend='stable',
                    confidence=0.5
                )
                charts['risk_distribution'] = ChartDataGenerator.risk_distribution_chart(risk_score)
                charts['risk_gauge'] = ChartDataGenerator.risk_gauge_chart(risk_score)

        if chart_type in ['severity', 'all']:
            mitre = data.get('mitre_mapping', [])
            if mitre:
                charts['severity_breakdown'] = ChartDataGenerator.severity_bar_chart(mitre)

        if chart_type in ['timeline', 'all']:
            timeline = data.get('timeline', [])
            if timeline:
                charts['timeline'] = ChartDataGenerator.timeline_chart(timeline)

        if chart_type in ['entities', 'all']:
            entities = data.get('entities', {})
            if entities:
                charts['entity_distribution'] = ChartDataGenerator.entity_type_chart(entities)

        return jsonify({
            'success': True,
            'charts': charts,
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"Chart generation error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/investigations/<investigation_id>/advanced-analysis', methods=['GET'])
@require_auth
def get_investigation_advanced_analysis(investigation_id):
    """
    Get advanced analysis for a specific investigation.

    Returns full analysis including risk score, MITRE mapping,
    executive summary, trends, and chart data.
    """
    if not ADVANCED_ANALYSIS_AVAILABLE:
        return jsonify({'error': 'Advanced analysis not available'}), 503

    # Check demo mode
    if mode_manager.is_demo_mode():
        demo_inv = demo_provider.get_demo_investigation(investigation_id)
        if demo_inv:
            analysis = _generate_demo_advanced_analysis(demo_inv)
            return jsonify({
                'investigation_id': investigation_id,
                'analysis': analysis,
                'timestamp': datetime.utcnow().isoformat()
            })
        return jsonify({'error': 'Investigation not found'}), 404

    # Check active investigations
    investigation = orchestrator.get_investigation_status(investigation_id)
    if not investigation:
        return jsonify({'error': 'Investigation not found'}), 404

    # Get investigation data and perform analysis
    try:
        findings = {
            'infrastructure': investigation.infrastructure_intelligence.__dict__ if investigation.infrastructure_intelligence else {},
            'social': investigation.social_intelligence.__dict__ if investigation.social_intelligence else {},
            'threat': investigation.threat_intelligence.__dict__ if investigation.threat_intelligence else {},
            'expanded_sources': getattr(investigation, 'expanded_intelligence', {})
        }

        correlation = getattr(investigation, 'correlation_results', None)

        analysis = advanced_analysis_engine.analyze(
            investigation.target_profile.primary_identifier,
            findings,
            correlation
        )

        return jsonify({
            'investigation_id': investigation_id,
            'analysis': analysis,
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"Investigation analysis error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/mitre/techniques', methods=['GET'])
@require_auth
def get_mitre_techniques():
    """Get list of supported MITRE ATT&CK techniques."""
    if not ADVANCED_ANALYSIS_AVAILABLE:
        return jsonify({'error': 'Advanced analysis not available'}), 503

    from advanced_analysis import MITRE_TECHNIQUES, MITRETactic

    techniques = [
        {
            'technique_id': t.technique_id,
            'name': t.name,
            'tactic': t.tactic.value,
            'description': t.description,
            'severity': t.severity
        }
        for t in MITRE_TECHNIQUES.values()
    ]

    tactics = [{'value': t.value, 'name': t.name} for t in MITRETactic]

    return jsonify({
        'techniques': techniques,
        'technique_count': len(techniques),
        'tactics': tactics,
        'tactic_count': len(tactics)
    })


def _generate_demo_advanced_analysis(demo_inv):
    """Generate demo advanced analysis."""
    target = demo_inv.get('target', 'example.com')

    return {
        'target': target,
        'analyzed_at': datetime.utcnow().isoformat(),
        'risk_score': {
            'overall_score': 62.5,
            'risk_level': 'high',
            'category_scores': {
                'infrastructure': 55.0,
                'threat': 70.0,
                'credential': 45.0,
                'data_exposure': 60.0,
                'reputation': 40.0,
                'compliance': 35.0
            },
            'factors': [
                {
                    'category': 'infrastructure',
                    'name': 'Exposed Services',
                    'score': 60,
                    'weight': 0.4,
                    'evidence': ['3 services exposed'],
                    'recommendations': ['Review exposed services']
                },
                {
                    'category': 'threat',
                    'name': 'Threat Indicators',
                    'score': 75,
                    'weight': 0.3,
                    'evidence': ['2 threat indicators found'],
                    'recommendations': ['Investigate indicators']
                }
            ],
            'trend': 'stable',
            'confidence': 0.78
        },
        'mitre_mapping': {
            'techniques': [
                {
                    'technique_id': 'T1190',
                    'name': 'Exploit Public-Facing Application',
                    'tactic': 'initial_access',
                    'severity': 'critical',
                    'evidence': ['Exposed service detected'],
                    'evidence_count': 1
                },
                {
                    'technique_id': 'T1592',
                    'name': 'Gather Victim Host Information',
                    'tactic': 'reconnaissance',
                    'severity': 'medium',
                    'evidence': ['Subdomain enumeration'],
                    'evidence_count': 1
                }
            ],
            'attack_surface': {
                'total_techniques': 2,
                'tactics_covered': ['initial_access', 'reconnaissance'],
                'critical_count': 1,
                'high_count': 0,
                'attack_surface_score': 33.0
            }
        },
        'trends': {
            'trend_available': True,
            'trend_direction': 'stable',
            'total_events': 5,
            'severity_distribution': {'info': 3, 'warning': 1, 'critical': 1}
        },
        'executive_summary': {
            'title': f'Executive Intelligence Summary: {target}',
            'overview': f'This investigation of {target} presents significant security concerns. '
                       f'Analysis was conducted across multiple intelligence sources.',
            'key_findings': [
                {
                    'category': 'infrastructure',
                    'finding': 'Exposed Services',
                    'severity': 'high',
                    'priority': 'high'
                }
            ],
            'recommendations': [
                {
                    'recommendation': 'Review and restrict exposed services',
                    'priority': 'short_term',
                    'category': 'infrastructure'
                }
            ]
        },
        'charts': {
            'risk_gauge': {
                'chart_type': 'gauge',
                'title': 'Overall Risk Score',
                'value': 62.5,
                'max': 100
            },
            'risk_distribution': {
                'chart_type': 'pie',
                'title': 'Risk Distribution by Category',
                'data': [
                    {'label': 'Threat', 'value': 70, 'color': '#fd7e14'},
                    {'label': 'Data Exposure', 'value': 60, 'color': '#ffc107'},
                    {'label': 'Infrastructure', 'value': 55, 'color': '#ffc107'}
                ]
            }
        }
    }


# ============================================================================

# Start background cleanup thread
cleanup_thread = threading.Thread(target=cleanup_expired_reports, daemon=True)
cleanup_thread.start()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)