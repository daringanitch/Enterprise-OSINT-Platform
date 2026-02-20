#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.

"""
Health Check Blueprint - Kubernetes probes, metrics, system status monitoring.
"""

import os
import logging
import psycopg2
from datetime import datetime
from flask import Blueprint, jsonify, g

from shared import services
from api_connection_monitor import APIType, APIStatus

# Try to import validators
try:
    from validators import get_safe_error_message
except ImportError:
    def get_safe_error_message(t, d=None): return d or 'An error occurred'

logger = logging.getLogger(__name__)

bp = Blueprint('health', __name__)


@bp.route('/metrics')
def metrics():
    """Prometheus metrics endpoint"""
    from flask import Response
    # get_metrics() not available without observability module
    return Response("# Metrics endpoint disabled\n", mimetype='text/plain')


@bp.route('/health')
def health():
    """Basic health check - is the service running?"""
    return jsonify({
        'status': 'healthy',
        'service': 'osint-backend',
        'timestamp': datetime.utcnow().isoformat(),
        'trace_id': getattr(g, 'trace_id', None)
    })


@bp.route('/health/live')
def liveness():
    """Kubernetes liveness probe - is the service alive?"""
    # Basic check that the service can respond
    return jsonify({
        'status': 'alive',
        'service': 'osint-backend',
        'timestamp': datetime.utcnow().isoformat(),
        'trace_id': getattr(g, 'trace_id', None)
    }), 200


@bp.route('/health/ready')
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
        if services.audit_client and services.audit_client.test_connection():
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
        if services.vault_client and services.vault_client.is_healthy():
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
        if services.api_monitor:
            system_status = services.api_monitor.get_system_status()
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
        job_queue_health = services.job_queue_manager.health_check()
        if job_queue_health['status'] == 'healthy':
            checks['checks']['job_queue'] = {
                'status': 'healthy',
                'redis_connection': job_queue_health.get('redis_connection', 'unknown'),
                'queues': len(job_queue_health.get('queues', [])),
                'workers': len(job_queue_health.get('workers', []))
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


@bp.route('/ready')
def ready():
    """Legacy ready endpoint - redirect to new health/ready"""
    return readiness()


@bp.route('/api/system/status', methods=['GET'])
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

        if services.audit_client:
            postgres_status['connected'] = services.audit_client.test_connection()

        # Check Vault connectivity
        vault_status = {
            'connected': services.vault_client.is_healthy(),
            'url': services.vault_client.vault_config.url if hasattr(services.vault_client, 'vault_config') else 'unknown',
            'mount_point': services.vault_client.vault_config.mount_point if hasattr(services.vault_client, 'vault_config') else 'unknown'
        }

        # Get API monitoring status
        api_system_status = services.api_monitor.get_system_status()
        api_status_by_type = {}

        for api_type in APIType:
            apis_of_type = services.api_monitor.get_apis_by_type(api_type)
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
            'active_investigations': len(services.orchestrator.active_investigations),
            'total_reports': len(services.reports),
            'audit_logging': 'postgresql' if services.audit_client else 'memory',
            'configuration_storage': 'vault' if services.vault_client.is_healthy() else 'environment',
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
        logger.error(f"System status check - database/connection error: {str(e)}", exc_info=True)
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
