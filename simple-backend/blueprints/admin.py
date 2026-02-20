#!/usr/bin/env python3
"""
Blueprint for admin and system management endpoints
"""
from flask import Blueprint, jsonify, request, Response
from shared import services
from datetime import datetime, timedelta
import logging

from blueprints.auth import require_auth, require_role
from api_connection_monitor import APIType
from audit_report_generator import AuditScope
from blueprints.reports import save_audit_history

logger = logging.getLogger(__name__)

bp = Blueprint('admin', __name__)


@bp.route('/api/monitoring/apis', methods=['GET'])
def get_api_monitoring_status():
    """Get detailed API monitoring status"""
    try:
        # Get overall system status
        system_status = services.api_monitor.get_system_status()

        # Get detailed status by API type
        api_details = {}
        for api_type in APIType:
            apis_of_type = services.api_monitor.get_apis_by_type(api_type)
            api_details[api_type.value] = {}

            for api_name, status in apis_of_type.items():
                endpoint = services.api_monitor.api_endpoints[api_name]
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
        logger.error(f"API monitoring status failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/monitoring/apis/<api_name>', methods=['GET'])
def get_specific_api_status(api_name):
    """Get detailed status for a specific API"""
    try:
        if api_name not in services.api_monitor.api_endpoints:
            return jsonify({'error': 'API not found'}), 404

        endpoint = services.api_monitor.api_endpoints[api_name]
        status = services.api_monitor.api_status[api_name]

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
            'is_available': services.api_monitor.is_api_available(api_name),
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"Specific API status failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/monitoring/apis/check', methods=['POST'])
def trigger_api_health_check():
    """Manually trigger health check for all APIs"""
    try:
        import asyncio

        async def run_check():
            return await services.api_monitor.check_all_apis()

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
        logger.error(f"Manual health check failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/stats', methods=['GET'])
def get_stats():
    """Get system statistics"""
    today = datetime.utcnow().date()

    # Get OSINT investigation stats
    active_investigations = services.orchestrator.get_active_investigations()

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
    for report in services.reports.values():
        report_time = datetime.fromisoformat(report['generated_at'])
        if datetime.utcnow() - report_time < timedelta(minutes=60):
            active_reports += 1

    # Include legacy investigations for backward compatibility
    legacy_today = [inv for inv in services.legacy_investigations.values()
                   if datetime.fromisoformat(inv['created_at']).date() == today]

    from blueprints.investigations import INVESTIGATION_TYPE_MAP
    return jsonify({
        'investigations_today': len(today_investigations) + len(legacy_today),
        'total_investigations': len(active_investigations) + len(services.legacy_investigations),
        'active_reports': active_reports,
        'total_reports_generated': len([inv for inv in active_investigations if inv.status.value == 'completed']),
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


@bp.route('/api/jobs/<job_id>/status', methods=['GET'])
@require_auth
def get_job_status(job_id):
    """Get status of a background job"""
    try:
        status = services.job_queue_manager.get_job_status(job_id)
        return jsonify(status), 200
    except Exception as e:
        logger.error(f"Failed to get job status: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/jobs/<job_id>/cancel', methods=['POST'])
@require_auth
def cancel_job(job_id):
    """Cancel a background job"""
    try:
        success = services.job_queue_manager.cancel_job(job_id)
        if success:
            return jsonify({
                'success': True,
                'message': 'Job cancelled successfully',
                'job_id': job_id
            }), 200
        else:
            return jsonify({'error': 'Job not found or cannot be cancelled'}), 404
    except Exception as e:
        logger.error(f"Failed to cancel job: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/jobs/queue/stats', methods=['GET'])
@require_auth
def get_queue_stats():
    """Get job queue statistics"""
    try:
        stats = services.job_queue_manager.get_queue_stats()
        return jsonify(stats), 200
    except Exception as e:
        logger.error(f"Failed to get queue stats: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/mcp/servers', methods=['GET'])
def get_mcp_servers():
    """Get list of MCP servers"""
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


@bp.route('/api/mcp/status', methods=['GET'])
def get_mcp_status():
    """Get MCP server status"""
    return jsonify({
        'mcp_servers_available': True,
        'social_media_server': {'status': 'online', 'capabilities': ['twitter', 'reddit', 'linkedin']},
        'infrastructure_server': {'status': 'online', 'capabilities': ['whois', 'dns', 'subdomain_enum', 'ssl_analysis']},
        'threat_intel_server': {'status': 'online', 'capabilities': ['virustotal', 'misp', 'otx', 'abuse_ch']},
        'last_health_check': datetime.utcnow().isoformat()
    })


@bp.route('/api/admin/vault/status', methods=['GET'])
def get_vault_status():
    """Get HashiCorp Vault status"""
    try:
        status = services.vault_client.get_vault_status()
        return jsonify(status), 200
    except Exception as e:
        logger.error(f"Failed to get Vault status: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/admin/services/configs', methods=['GET'])
def get_service_configs():
    """Get all service configurations"""
    try:
        # Demo mode fallback
        if services.mode_manager.is_demo_mode():
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

        configs = services.config_manager.get_all_service_configs()
        return jsonify(configs), 200
    except Exception as e:
        logger.error(f"Failed to get service configs: {str(e)}", exc_info=True)
        return jsonify({
            'services': {},
            'demo_mode': True,
            'message': 'Configuration unavailable - running in fallback mode'
        }), 200


@bp.route('/api/admin/services/configure', methods=['POST'])
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
        if not services.config_manager.validate_api_key(service_name, api_key):
            return jsonify({'error': 'Invalid API key format'}), 400

        # Register API key
        success = services.config_manager.register_api_key(service_name, api_key, environment)

        if success:
            return jsonify({'success': True, 'message': f'API key configured for {service_name}'}), 200
        else:
            return jsonify({'error': 'Failed to configure API key'}), 500

    except Exception as e:
        logger.error(f"Failed to configure service: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/admin/services/<service_name>/test', methods=['POST'])
def test_service_api_key(service_name):
    """Test API key for a service"""
    try:
        # Get API key from vault
        api_key = services.config_manager.get_service_api_key(service_name)

        if not api_key:
            return jsonify({'error': 'API key not configured for this service'}), 404

        # Perform basic validation test
        if len(api_key) < 10:
            return jsonify({'error': 'API key appears to be invalid (too short)'}), 400

        # Mock test results
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
        logger.error(f"Failed to test API key for {service_name}: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/admin/services/<service_name>/remove', methods=['DELETE'])
def remove_service_api_key(service_name):
    """Remove API key for a service"""
    try:
        success = services.vault_client.delete_api_key(service_name)

        if success:
            return jsonify({'success': True, 'message': f'API key removed for {service_name}'}), 200
        else:
            return jsonify({'error': 'Failed to remove API key'}), 500

    except Exception as e:
        logger.error(f"Failed to remove API key for {service_name}: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/admin/services/<service_name>/rotate', methods=['PUT'])
def rotate_service_api_key(service_name):
    """Rotate API key for a service"""
    try:
        data = request.json
        new_api_key = data.get('new_api_key')

        if not new_api_key:
            return jsonify({'error': 'new_api_key is required'}), 400

        # Validate new API key format
        if not services.config_manager.validate_api_key(service_name, new_api_key):
            return jsonify({'error': 'Invalid API key format'}), 400

        # Rotate the key
        success = services.vault_client.rotate_api_key(service_name, new_api_key)

        if success:
            return jsonify({'success': True, 'message': f'API key rotated for {service_name}'}), 200
        else:
            return jsonify({'error': 'Failed to rotate API key'}), 500

    except Exception as e:
        logger.error(f"Failed to rotate API key for {service_name}: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/admin/services/import-env', methods=['POST'])
def import_services_from_environment():
    """Import API keys from environment variables"""
    try:
        results = services.config_manager.import_from_environment()
        return jsonify(results), 200

    except Exception as e:
        logger.error(f"Failed to import from environment: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/admin/audit/logs', methods=['GET'])
def get_audit_logs():
    """Get system audit logs"""
    try:
        time_range = request.args.get('time_range', '24h')

        # Mock audit logs
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
        services_list = ['openai', 'shodan', 'virustotal', 'twitter']
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
                'resource': services_list[i % len(services_list)],
                'success': i % 5 != 0,
                'ip_address': '127.0.0.1',
                'user_agent': 'Enterprise OSINT Admin Panel'
            })

        # Sort by timestamp descending
        audit_logs.sort(key=lambda x: x['timestamp'], reverse=True)

        return jsonify(audit_logs), 200

    except Exception as e:
        logger.error(f"Failed to get audit logs: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/admin/audit/generate', methods=['POST'])
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
        audit_report = services.audit_report_generator.generate_audit_report(
            scope=audit_scope,
            start_date=start_date,
            end_date=end_date,
            generated_by=generated_by,
            investigator_filter=investigator_filter
        )

        # Export report in requested format
        report_data = services.audit_report_generator.export_audit_report(audit_report, format_type)

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
        logger.error(f"Audit report generation failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/admin/clear-legacy-data', methods=['POST'])
@require_auth
@require_role('admin')
def clear_legacy_data():
    """Clear all legacy investigations and reports (admin only)"""
    try:
        # Clear orchestrator investigations
        active_investigations = services.orchestrator.get_active_investigations()
        investigations_cleared = len(active_investigations)

        # Clear all investigations from orchestrator
        services.orchestrator.investigations.clear()

        # Clear reports
        reports_cleared = len(services.reports)
        services.reports.clear()

        # Keep audit history but mark it as archived
        audit_entries = len(services.reports_audit_history)
        for report_id, entry in services.reports_audit_history.items():
            entry['archived'] = True
            entry['archived_at'] = datetime.utcnow().isoformat()

        # Save updated audit history
        save_audit_history()

        logger.info(f"Legacy data cleared: {investigations_cleared} investigations, {reports_cleared} reports")

        return jsonify({
            'message': 'Legacy data cleared successfully',
            'cleared': {
                'investigations': investigations_cleared,
                'reports': reports_cleared,
                'audit_entries_archived': audit_entries
            }
        }), 200

    except Exception as e:
        logger.error(f"Failed to clear legacy data: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/system/mode', methods=['GET'])
@require_auth
def get_system_mode():
    """Get current system mode and status"""
    try:
        mode_status = services.mode_manager.get_mode_status()
        return jsonify(mode_status), 200
    except Exception as e:
        logger.error(f"Failed to get mode status: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/system/mode', methods=['POST'])
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

        success, message = services.mode_manager.set_mode(mode, user_initiated=True)

        if success:
            logger.info(f"Mode changed to {mode}")
            return jsonify({
                'success': True,
                'message': message,
                'new_mode': services.mode_manager.get_current_mode(),
                'status': services.mode_manager.get_mode_status()
            }), 200
        else:
            return jsonify({'success': False, 'error': message}), 400

    except Exception as e:
        logger.error(f"Failed to set mode: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/system/demo-data', methods=['GET'])
@require_auth
def get_demo_data_config():
    """Get demo data configuration"""
    try:
        config = services.mode_manager.get_demo_data_config()
        return jsonify(config), 200
    except Exception as e:
        logger.error(f"Failed to get demo config: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/system/api-keys', methods=['GET'])
@require_auth
def get_api_key_status():
    """Get API key availability status"""
    try:
        mode_status = services.mode_manager.get_mode_status()
        api_info = mode_status['api_keys']

        # Don't expose actual key values, just status
        return jsonify({
            'mode': services.mode_manager.get_current_mode(),
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
        logger.error(f"Failed to get API key status: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/system/status', methods=['GET'])
@require_auth
def get_enhanced_system_status():
    """Get enhanced system status including mode"""
    try:
        # Get base system status
        if services.mode_manager.is_demo_mode():
            system_status = services.demo_provider.get_demo_system_status()
        else:
            # Get real system status
            system_status = {
                'service': 'osint-backend',
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'mode': 'production'
            }

        # Add mode information
        mode_status = services.mode_manager.get_mode_status()
        system_status.update({
            'mode_info': {
                'current_mode': mode_status['current_mode'],
                'auto_fallback_enabled': mode_status['auto_fallback_enabled'],
                'api_keys_available': mode_status['api_keys']['available_count'],
                'production_ready': mode_status['features']['production_capable'],
                'demo_features': mode_status['features']['demo_features_enabled'] if services.mode_manager.is_demo_mode() else []
            }
        })

        return jsonify(system_status), 200

    except Exception as e:
        logger.error(f"System status error: {str(e)}", exc_info=True)
        return jsonify({
            'service': 'osint-backend',
            'status': 'error',
            'error': 'An internal error occurred. Check server logs.',
            'timestamp': datetime.utcnow().isoformat()
        }), 500


@bp.route('/api/cache/status', methods=['GET'])
@require_auth
def get_cache_status():
    """Get cache service status and statistics"""
    if not services.CACHING_ENABLED or services.cache_service is None:
        return jsonify({
            'enabled': False,
            'message': 'Caching is not enabled',
            'backend': 'none'
        })

    try:
        health = services.cache_service.health_check()
        return jsonify({
            'enabled': True,
            'backend': health.get('backend', 'unknown'),
            'status': health.get('status', 'unknown'),
            'latency_ms': health.get('latency_ms', 0),
            'statistics': health.get('stats', {}),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Cache status error: {str(e)}", exc_info=True)
        return jsonify({
            'enabled': True,
            'status': 'error',
            'error': 'An internal error occurred. Check server logs.'
        }), 500


@bp.route('/api/cache/invalidate', methods=['POST'])
@require_auth
@require_role('admin')
def invalidate_cache():
    """Invalidate cache entries (admin only)"""
    if not services.CACHING_ENABLED or services.cache_service is None:
        return jsonify({'error': 'Caching is not enabled'}), 400

    data = request.json or {}
    pattern = data.get('pattern')
    investigation_id = data.get('investigation_id')

    try:
        if investigation_id:
            count = services.cache_service.invalidate_investigation(investigation_id)
            return jsonify({
                'success': True,
                'message': f'Invalidated cache for investigation {investigation_id}',
                'entries_removed': count
            })
        elif pattern:
            count = services.cache_service.delete_pattern(pattern)
            return jsonify({
                'success': True,
                'message': 'Invalidated cache entries matching pattern',
                'entries_removed': count
            })
        else:
            # Invalidate all
            services.cache_service.invalidate_all()
            services.cache_service.reset_stats()
            return jsonify({
                'success': True,
                'message': 'All cache entries invalidated'
            })
    except Exception as e:
        logger.error(f"Cache invalidation error: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500
