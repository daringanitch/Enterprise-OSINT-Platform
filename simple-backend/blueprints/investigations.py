#!/usr/bin/env python3
"""
Blueprint for OSINT investigation endpoints
"""
from flask import Blueprint, jsonify, request, g
from shared import services
from datetime import datetime, timedelta
import logging
import uuid
from blueprints.auth import require_auth

from models import InvestigationType, Priority, InvestigationStatus, InvestigationScope
from api_connection_monitor import APIType
from problem_json import InvestigationNotFoundError

logger = logging.getLogger(__name__)

bp = Blueprint('investigations', __name__)

# Investigation type and priority mappings
INVESTIGATION_TYPE_MAP = {
    'comprehensive': InvestigationType.COMPREHENSIVE,
    'infrastructure': InvestigationType.INFRASTRUCTURE,
    'social_media': InvestigationType.SOCIAL_MEDIA,
    'threat_assessment': InvestigationType.THREAT_ASSESSMENT,
    'corporate': InvestigationType.CORPORATE
}

PRIORITY_MAP = {
    'low': Priority.LOW,
    'normal': Priority.NORMAL,
    'high': Priority.HIGH,
    'urgent': Priority.URGENT,
    'critical': Priority.CRITICAL
}


@bp.route('/api/investigations', methods=['GET'])
@require_auth
def get_investigations():
    """Get all OSINT investigations with detailed status"""
    result = []

    # Check if we're in demo mode
    if services.mode_manager.is_demo_mode():
        logger.info("Serving demo investigations data")
        demo_investigations = services.demo_provider.generate_demo_investigations(count=5)
        return jsonify(demo_investigations)

    # Get active OSINT investigations (production mode)
    active_investigations = services.orchestrator.get_active_investigations()
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
        if report_id in services.reports:
            report = services.reports[report_id]
            report_time = datetime.fromisoformat(report['generated_at'])
            if datetime.utcnow() - report_time < timedelta(minutes=60):
                inv_data['report_available'] = True
                inv_data['report_expires_at'] = (report_time + timedelta(minutes=60)).isoformat()
            else:
                inv_data['report_available'] = False
                del services.reports[report_id]
        else:
            inv_data['report_available'] = False

        result.append(inv_data)

    # Also include legacy investigations for backward compatibility
    for inv in services.legacy_investigations.values():
        inv_data = inv.copy()
        report_id = f"report_{inv['id']}"
        if report_id in services.reports:
            report = services.reports[report_id]
            report_time = datetime.fromisoformat(report['generated_at'])
            if datetime.utcnow() - report_time < timedelta(minutes=60):
                inv_data['report_available'] = True
                inv_data['report_expires_at'] = (report_time + timedelta(minutes=60)).isoformat()
            else:
                inv_data['report_available'] = False
                del services.reports[report_id]
        else:
            inv_data['report_available'] = False
        result.append(inv_data)

    return jsonify(result)


@bp.route('/api/investigations', methods=['POST'])
@require_auth
def create_investigation():
    """Create a new OSINT investigation"""
    data = request.json or {}

    try:
        # Validate and sanitize input using Pydantic models
        if services.VALIDATION_ENABLED:
            try:
                from validators import validate_investigation_request, ValidationError as InputValidationError
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
        available_ai_apis = services.api_monitor.get_available_apis(APIType.AI_ML)

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

        # Start investigation — creates record AND submits to ThreadPoolExecutor
        # so it executes immediately in the background within this process.
        # (The two-step create+enqueue pattern relied on MockJobQueueManager
        # which was a no-op; start_investigation is the reliable path.)
        investigation_id = services.orchestrator.start_investigation(
            target=target,
            investigation_type=inv_type,
            investigator_name=investigator_name,
            priority=inv_priority,
            scope=scope
        )
        job_id = investigation_id  # thread future is tracked internally

        # Get investigation details
        investigation = services.orchestrator.get_investigation(investigation_id)
        if not investigation:
            return jsonify({'error': 'Failed to create investigation'}), 500

        # Store job ID for progress tracking
        investigation.job_id = job_id

        # Ensure the investigation object has the correct investigator_id
        investigation.investigator_id = investigator_id

        # Log investigation start to PostgreSQL audit system
        if services.audit_client:
            from postgres_audit_client import log_investigation_start, AuditEvent, EventType
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
            services.audit_client.log_audit_event(event)

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
            'fallback_mode': services.api_monitor.get_system_status()['fallback_mode'],
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
        logger.error(f"Failed to create investigation: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/investigations/<inv_id>', methods=['GET'])
def get_investigation(inv_id):
    """Get a specific OSINT investigation"""
    # Handle demo mode
    if services.mode_manager.is_demo_mode():
        demo_inv = services.demo_provider.get_demo_investigation(inv_id)
        if demo_inv:
            return jsonify(demo_inv)
        return jsonify({'error': 'Demo investigation not found', 'investigation_id': inv_id}), 404

    # Try to get OSINT investigation first (production mode)
    investigation = services.orchestrator.get_investigation(inv_id)

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
        if report_id in services.reports:
            report = services.reports[report_id]
            report_time = datetime.fromisoformat(report['generated_at'])
            if datetime.utcnow() - report_time < timedelta(minutes=60):
                inv_data['report_available'] = True
                inv_data['report_expires_at'] = (report_time + timedelta(minutes=60)).isoformat()
                inv_data['report_data'] = report
            else:
                inv_data['report_available'] = False
                del services.reports[report_id]
        else:
            inv_data['report_available'] = False
            # Can generate report if investigation is completed
            inv_data['can_generate_report'] = investigation.status == InvestigationStatus.COMPLETED

        return jsonify(inv_data)

    # Fallback to legacy investigations
    if inv_id not in services.legacy_investigations:
        return jsonify({'error': 'Investigation not found'}), 404

    inv = services.legacy_investigations[inv_id].copy()

    # Check report status for legacy investigation
    report_id = f"report_{inv_id}"
    if report_id in services.reports:
        report = services.reports[report_id]
        report_time = datetime.fromisoformat(report['generated_at'])
        if datetime.utcnow() - report_time < timedelta(minutes=60):
            inv['report_available'] = True
            inv['report_expires_at'] = (report_time + timedelta(minutes=60)).isoformat()
            inv['report_data'] = report
        else:
            inv['report_available'] = False
            del services.reports[report_id]
    else:
        inv['report_available'] = False

    return jsonify(inv)


@bp.route('/api/investigations/<inv_id>/cancel', methods=['POST'])
def cancel_investigation(inv_id):
    """Cancel a running OSINT investigation"""
    success = services.orchestrator.cancel_investigation(inv_id)

    if success:
        return jsonify({
            'message': 'Investigation cancelled successfully',
            'investigation_id': inv_id
        })
    else:
        return jsonify({'error': 'Investigation not found or cannot be cancelled'}), 404


@bp.route('/api/investigations/<inv_id>/progress', methods=['GET'])
def get_investigation_progress(inv_id):
    """Get real-time progress for an investigation"""
    # Handle demo mode
    if services.mode_manager.is_demo_mode():
        demo_inv = services.demo_provider.get_demo_investigation(inv_id)
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

    investigation = services.orchestrator.get_investigation(inv_id)

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


@bp.route('/api/investigations/<investigation_id>/advanced-analysis', methods=['GET'])
@require_auth
def investigation_advanced_analysis(investigation_id):
    """Get advanced analysis for a specific investigation"""
    if not services.ADVANCED_ANALYSIS_AVAILABLE:
        return jsonify({'error': 'Advanced analysis not available'}), 503

    # Check demo mode
    if services.mode_manager.is_demo_mode():
        demo_inv = services.demo_provider.get_demo_investigation(investigation_id)
        if demo_inv:
            from blueprints.analysis import _generate_demo_advanced_analysis
            analysis = _generate_demo_advanced_analysis(demo_inv)
            return jsonify({
                'investigation_id': investigation_id,
                'analysis': analysis,
                'timestamp': datetime.utcnow().isoformat()
            })
        return jsonify({'error': 'Investigation not found'}), 404

    # Check active investigations
    investigation = services.orchestrator.get_investigation(investigation_id)
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

        analysis = services.advanced_analysis_engine.analyze(
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
        logger.error(f"Investigation analysis error: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500
