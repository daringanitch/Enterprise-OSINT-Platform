#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.

"""
Enterprise OSINT Platform Backend - Refactored with Blueprint Architecture
Full Intelligence Gathering and Analysis System
"""
import os
import logging
from flask import Flask
from flask_cors import CORS
from datetime import datetime

# Configure logging early
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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

# Feature flags for optional services
VALIDATION_ENABLED = False
CACHING_ENABLED = False
GRAPH_INTELLIGENCE_AVAILABLE = False
EXPANDED_SOURCES_AVAILABLE = False
CORRELATION_AVAILABLE = False
ADVANCED_ANALYSIS_AVAILABLE = False

# Try importing optional validators
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
    def validate_compliance_request(data): return data
    def validate_risk_request(data): return data
    def get_safe_error_message(t, d=None): return d or 'An error occurred'

# Try importing caching service
try:
    from cache_service import cache_service, cached, CacheTTL, cached_response
    CACHING_ENABLED = True
except ImportError:
    CACHING_ENABLED = False
    cache_service = None
    def cached(*args, **kwargs):
        def decorator(func): return func
        return decorator
    def cached_response(*args, **kwargs):
        def decorator(func): return func
        return decorator
    class CacheTTL:
        SHORT = 60
        MEDIUM = 300
        LONG = 900
        EXTENDED = 3600

# Try importing expanded data sources
try:
    from expanded_data_sources import expanded_data_manager, DataSourceType
    EXPANDED_SOURCES_AVAILABLE = True
except ImportError:
    EXPANDED_SOURCES_AVAILABLE = False
    expanded_data_manager = None

# Try importing intelligence correlation
try:
    from intelligence_correlation import IntelligenceCorrelator, EntityType, RelationshipType
    CORRELATION_AVAILABLE = True
except ImportError:
    CORRELATION_AVAILABLE = False
    IntelligenceCorrelator = None

# Try importing advanced analysis
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

# Try importing graph intelligence
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

# Mock job queue for Docker compatibility
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

# Dummy decorators for Docker compatibility
def trace_operation(operation_name):
    def decorator(func):
        return func
    return decorator

def trace_investigation(func):
    return func

# Create Flask app
app = Flask(__name__)
CORS(app,
     origins=['http://localhost:8080', 'http://localhost:*', 'http://127.0.0.1:*', 'http://localhost:5001'],
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])

# Global error handlers
@app.errorhandler(400)
def bad_request_handler(error):
    """Handle bad request errors"""
    logger.warning(f"Bad request: {str(error)}")
    from flask import jsonify
    return jsonify({
        'error': 'Bad Request',
        'message': get_safe_error_message('validation_error', 'Invalid request data')
    }), 400

@app.errorhandler(401)
def unauthorized_handler(error):
    """Handle unauthorized errors"""
    from flask import jsonify
    return jsonify({
        'error': 'Unauthorized',
        'message': get_safe_error_message('authentication_error')
    }), 401

@app.errorhandler(403)
def forbidden_handler(error):
    """Handle forbidden errors"""
    from flask import jsonify
    return jsonify({
        'error': 'Forbidden',
        'message': get_safe_error_message('authorization_error')
    }), 403

@app.errorhandler(404)
def not_found_handler(error):
    """Handle not found errors"""
    from flask import jsonify
    return jsonify({
        'error': 'Not Found',
        'message': get_safe_error_message('not_found', 'Resource not found')
    }), 404

@app.errorhandler(429)
def rate_limit_handler(error):
    """Handle rate limit errors"""
    from flask import jsonify
    logger.warning(f"Rate limit exceeded")
    return jsonify({
        'error': 'Too Many Requests',
        'message': get_safe_error_message('rate_limit')
    }), 429

@app.errorhandler(500)
def internal_error_handler(error):
    """Handle internal server errors - never expose details"""
    from flask import jsonify
    logger.error(f"Internal server error: {str(error)}", exc_info=True)
    return jsonify({
        'error': 'Internal Server Error',
        'message': get_safe_error_message('internal_error')
    }), 500

@app.errorhandler(503)
def service_unavailable_handler(error):
    """Handle service unavailable errors"""
    from flask import jsonify
    logger.error(f"Service unavailable: {str(error)}", exc_info=True)
    return jsonify({
        'error': 'Service Unavailable',
        'message': get_safe_error_message('service_unavailable')
    }), 503

# Session configuration
app.config['SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-secret-key-change-in-production')

# Initialize OSINT Investigation System
logger.info("Initializing core services...")
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
audit_client = None
try:
    audit_client = init_audit_client(
        host=os.getenv('POSTGRES_HOST', 'postgresql'),
        port=int(os.getenv('POSTGRES_PORT', '5432')),
        database=os.getenv('POSTGRES_DB', 'osint_audit'),
        username=os.getenv('POSTGRES_USER', 'postgres'),
        password=os.getenv('POSTGRES_PASSWORD', 'password123')
    )

    if audit_client.test_connection():
        logger.info("PostgreSQL audit client initialized successfully")
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
    logger.error(f"Failed to initialize PostgreSQL audit client: {e}", exc_info=True)
    audit_client = None

# Initialize Graph Intelligence API
graph_sync = None
if GRAPH_INTELLIGENCE_AVAILABLE and register_graph_api:
    try:
        register_graph_api(app)
        graph_sync = CorrelationSync()
        logger.info("Graph Intelligence API registered at /api/graph")
    except Exception as e:
        logger.error(f"Failed to initialize Graph Intelligence: {e}", exc_info=True)
        graph_sync = None
        GRAPH_INTELLIGENCE_AVAILABLE = False
else:
    logger.warning("Graph Intelligence not available")

# In-memory storage for testing
legacy_investigations = {}
reports = {}
reports_audit_history = {}

# File-based persistence for audit history
AUDIT_HISTORY_FILE = Path('/tmp/osint_audit_history.json')

from pathlib import Path
import json

def load_audit_history():
    """Load audit history from persistent storage"""
    global reports_audit_history
    if AUDIT_HISTORY_FILE.exists():
        try:
            with open(AUDIT_HISTORY_FILE, 'r') as f:
                reports_audit_history = json.load(f)
            logger.info(f"Loaded {len(reports_audit_history)} audit entries from file")
        except Exception as e:
            logger.error(f"Error loading audit history: {e}", exc_info=True)
            reports_audit_history = {}
    else:
        reports_audit_history = {}
        save_audit_history()

def save_audit_history():
    """Save audit history to persistent storage"""
    try:
        with open(AUDIT_HISTORY_FILE, 'w') as f:
            json.dump(reports_audit_history, f, indent=2)
        logger.info(f"Saved {len(reports_audit_history)} audit entries to file")
    except Exception as e:
        logger.error(f"Error saving audit history: {e}", exc_info=True)

# Load audit history on startup
load_audit_history()

# Populate shared services singleton
from shared import services
from utils.startup_validation import validate_secrets, SecurityStartupError

logger.info("Populating shared services...")
services.orchestrator = orchestrator
services.compliance_engine = compliance_engine
services.report_generator = report_generator
services.vault_client = vault_client
services.config_manager = config_manager
services.professional_report_generator = professional_report_generator
services.audit_report_generator = audit_report_generator
services.api_monitor = api_monitor
services.graph_sync = graph_sync
services.audit_client = audit_client
services.mode_manager = mode_manager
services.job_queue_manager = job_queue_manager
services.demo_provider = demo_provider

services.legacy_investigations = legacy_investigations
services.reports = reports
services.reports_audit_history = reports_audit_history

services.VALIDATION_ENABLED = VALIDATION_ENABLED
services.CACHING_ENABLED = CACHING_ENABLED
services.GRAPH_INTELLIGENCE_AVAILABLE = GRAPH_INTELLIGENCE_AVAILABLE
services.EXPANDED_SOURCES_AVAILABLE = EXPANDED_SOURCES_AVAILABLE
services.CORRELATION_AVAILABLE = CORRELATION_AVAILABLE
services.ADVANCED_ANALYSIS_AVAILABLE = ADVANCED_ANALYSIS_AVAILABLE

services.cache_service = cache_service
services.expanded_data_manager = expanded_data_manager
services.advanced_analysis_engine = advanced_analysis_engine

# Validate startup security
logger.info("Validating startup security...")
try:
    validate_secrets(is_demo=mode_manager.is_demo_mode())
    logger.info("Security validation passed")
except SecurityStartupError as e:
    logger.critical(f"Security startup validation failed: {e}")
    raise

# Register blueprints
logger.info("Registering blueprints...")
from blueprints.health import bp as health_bp
from blueprints.auth import bp as auth_bp

app.register_blueprint(health_bp)
app.register_blueprint(auth_bp)

logger.info("Application startup complete")

# Main entry point
if __name__ == '__main__':
    logger.info("Starting Enterprise OSINT Platform Backend")
    app.run(
        host='0.0.0.0',
        port=5001,
        debug=mode_manager.is_demo_mode(),
        use_reloader=False
    )
