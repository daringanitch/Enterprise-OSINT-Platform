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

# ============================================================================
# SHARED SERVICES SETUP
# Populate the shared services singleton before registering blueprints.
# All blueprints access services via `from shared import services`.
# ============================================================================

from shared import services
from utils.startup_validation import validate_secrets, SecurityStartupError

# ============================================================================
# SERVICE INITIALIZATION
# ============================================================================

# Initialize core services
orchestrator = InvestigationOrchestrator()
compliance_engine = ComplianceEngine()
vault_client = VaultClient(config=VaultConfig())
config_manager = ConfigurationManager(vault_client=vault_client)
report_generator = InvestigationReportGenerator(investigation_orchestrator=orchestrator)
professional_report_generator = ProfessionalReportGenerator()
audit_report_generator = ComprehensiveAuditReportGenerator(
    investigation_orchestrator=orchestrator,
    vault_client=vault_client,
    config_manager=config_manager
)
api_monitor = APIConnectionMonitor()
graph_sync = CorrelationSync() if GRAPH_INTELLIGENCE_AVAILABLE else None
audit_client = init_audit_client()

# In-memory data storage
legacy_investigations = {}
reports = {}
reports_audit_history = {}  # keyed by report_id

# Core service objects
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

# In-memory storage (shared by reference — mutations in blueprints are reflected here)
services.legacy_investigations = legacy_investigations
services.reports = reports
services.reports_audit_history = reports_audit_history

# Feature availability flags
services.VALIDATION_ENABLED = VALIDATION_ENABLED
services.CACHING_ENABLED = CACHING_ENABLED
services.GRAPH_INTELLIGENCE_AVAILABLE = GRAPH_INTELLIGENCE_AVAILABLE
services.EXPANDED_SOURCES_AVAILABLE = EXPANDED_SOURCES_AVAILABLE
services.CORRELATION_AVAILABLE = CORRELATION_AVAILABLE
services.ADVANCED_ANALYSIS_AVAILABLE = ADVANCED_ANALYSIS_AVAILABLE

# Optional service instances
services.cache_service = cache_service
services.expanded_data_manager = expanded_data_manager
services.advanced_analysis_engine = advanced_analysis_engine

# ============================================================================
# STARTUP SECURITY VALIDATION
# ============================================================================

try:
    validate_secrets(is_demo=mode_manager.is_demo_mode())
    logger.info("Startup security validation passed")
except SecurityStartupError as e:
    logger.critical(f"STARTUP FAILED — security validation error: {e}")
    raise

# ============================================================================
# BLUEPRINT REGISTRATION
# Each blueprint handles a specific domain. Routes are no longer defined
# in this file — they live in blueprints/<domain>.py.
# ============================================================================

logger.info("Registering Flask blueprints...")

from blueprints.health import bp as health_bp
from blueprints.auth import bp as auth_bp
from blueprints.investigations import bp as investigations_bp
from blueprints.reports import bp as reports_bp
from blueprints.compliance import bp as compliance_bp
from blueprints.risk import bp as risk_bp
from blueprints.intelligence import bp as intelligence_bp
from blueprints.graph import bp as graph_bp
from blueprints.analysis import bp as analysis_bp
from blueprints.admin import bp as admin_bp
from blueprints.nlp import bp as nlp_bp
from blueprints.stix import bp as stix_bp
from blueprints.credentials import bp as credentials_bp
from blueprints.settings import bp as settings_bp

app.register_blueprint(health_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(investigations_bp)
app.register_blueprint(reports_bp)
app.register_blueprint(compliance_bp)
app.register_blueprint(risk_bp)
app.register_blueprint(intelligence_bp)
app.register_blueprint(graph_bp)
app.register_blueprint(analysis_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(nlp_bp)
app.register_blueprint(stix_bp)
app.register_blueprint(credentials_bp)
app.register_blueprint(settings_bp)

logger.info("All blueprints registered successfully")

# ============================================================================
# BACKGROUND TASKS AND STARTUP HOOKS
# ============================================================================

def cleanup_expired_reports():
    """Background task to clean up expired reports"""
    while True:
        time.sleep(60)  # Check every minute
        expired_reports = []
        for report_id, report in reports.items():
            # Skip demo reports - they don't expire
            is_demo = report.get('content', {}).get('investigation_metadata', {}).get('demo_mode', False)
            if is_demo:
                continue

            report_time = datetime.fromisoformat(report['generated_at'])
            if datetime.utcnow() - report_time >= timedelta(minutes=60):
                expired_reports.append(report_id)

        for report_id in expired_reports:
            del reports[report_id]
            logger.info(f"Cleaned up expired report: {report_id}")

# Seed demo reports if in demo mode
def seed_demo_reports():
    """Seed sample reports when running in demo mode"""
    if mode_manager.is_demo_mode():
        demo_reports = demo_provider.get_demo_reports()
        for report in demo_reports:
            reports[report['id']] = report
        logger.info(f"Seeded {len(demo_reports)} demo reports")

# Initialize demo data
seed_demo_reports()

# Start background cleanup thread
cleanup_thread = threading.Thread(target=cleanup_expired_reports, daemon=True)
cleanup_thread.start()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)