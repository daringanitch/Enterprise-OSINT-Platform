#!/usr/bin/env python3
"""
Blueprint for report generation endpoints
"""
from flask import Blueprint, jsonify, request, g, Response
from shared import services
from datetime import datetime, timedelta
import logging
import json
from pathlib import Path
from blueprints.auth import require_auth

from models import InvestigationStatus
from investigation_reporting import ReportFormat, TimeRange
from professional_report_generator import ReportType, ReportFormat as ProfReportFormat, ClassificationLevel

logger = logging.getLogger(__name__)

bp = Blueprint('reports', __name__)

# Audit history file and functions
AUDIT_HISTORY_FILE = Path('/tmp/osint_audit_history.json')


def load_audit_history():
    """Load audit history from file"""
    if AUDIT_HISTORY_FILE.exists():
        try:
            with open(AUDIT_HISTORY_FILE, 'r') as f:
                data = json.load(f)
                services.reports_audit_history.update(data)
        except Exception as e:
            logger.error(f"Failed to load audit history: {str(e)}", exc_info=True)


def save_audit_history():
    """Save audit history to file for persistence"""
    try:
        with open(AUDIT_HISTORY_FILE, 'w') as f:
            json.dump(services.reports_audit_history, f, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to save audit history: {str(e)}", exc_info=True)


@bp.route('/api/investigations/<inv_id>/report', methods=['POST'])
@require_auth
def generate_report(inv_id):
    """Generate OSINT investigation report"""
    # Handle demo mode
    if services.mode_manager.is_demo_mode():
        demo_inv = services.demo_provider.get_demo_investigation(inv_id)
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
            demo_report_data = services.demo_provider.generate_demo_report_data(inv_id, target)

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

            services.reports[report_id] = report
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
    investigation = services.orchestrator.get_investigation(inv_id)

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

        services.reports[report_id] = report

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
        services.reports_audit_history[report_id] = audit_entry
        save_audit_history()

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
    if inv_id not in services.legacy_investigations:
        return jsonify({'error': 'Investigation not found'}), 404

    investigation = services.legacy_investigations[inv_id]
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

    services.reports[report_id] = report

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
    services.reports_audit_history[report_id] = audit_entry
    save_audit_history()

    return jsonify({
        'message': 'Report generated successfully',
        'report_id': report_id,
        'expires_at': report['expires_at'],
        'available_for_minutes': 60
    }), 201


@bp.route('/api/investigations/<inv_id>/report', methods=['GET'])
def get_report(inv_id):
    """Get a generated report"""
    report_id = f"report_{inv_id}"

    if report_id not in services.reports:
        return jsonify({'error': 'Report not found or expired'}), 404

    report = services.reports[report_id]
    report_time = datetime.fromisoformat(report['generated_at'])

    # Check if expired
    if datetime.utcnow() - report_time >= timedelta(minutes=60):
        del services.reports[report_id]
        return jsonify({'error': 'Report has expired'}), 410

    # Calculate time remaining
    expires_at = datetime.fromisoformat(report['expires_at'])
    time_remaining = expires_at - datetime.utcnow()

    response = report.copy()
    response['time_remaining_seconds'] = int(time_remaining.total_seconds())

    return jsonify(response)


@bp.route('/api/reports', methods=['GET'])
def get_all_reports():
    """Get all reports with expiration status"""
    result = []
    expired_reports = []

    for report_id, report in services.reports.items():
        # Skip expiration check for demo reports (they have demo_mode flag in metadata)
        is_demo = report.get('content', {}).get('investigation_metadata', {}).get('demo_mode', False)

        if is_demo:
            # Demo reports don't expire
            report_data = report.copy()
            report_data['time_remaining_seconds'] = 999999  # Long time remaining
            result.append(report_data)
        else:
            report_time = datetime.fromisoformat(report['generated_at'])
            if datetime.utcnow() - report_time >= timedelta(minutes=60):
                expired_reports.append(report_id)
            else:
                expires_at = datetime.fromisoformat(report['expires_at'])
                time_remaining = expires_at - datetime.utcnow()

                report_data = report.copy()
                report_data['time_remaining_seconds'] = int(time_remaining.total_seconds())
                result.append(report_data)

    # Clean up expired reports (not demo reports)
    for report_id in expired_reports:
        del services.reports[report_id]

    return jsonify(result)


@bp.route('/api/investigations/<inv_id>/report/download', methods=['GET'])
def download_report(inv_id):
    """Download report data"""
    report_id = f"report_{inv_id}"

    if report_id not in services.reports:
        return jsonify({'error': 'Report not found or expired'}), 404

    report = services.reports[report_id]
    report_time = datetime.fromisoformat(report['generated_at'])

    # Check if expired
    if datetime.utcnow() - report_time >= timedelta(minutes=60):
        del services.reports[report_id]
        return jsonify({'error': 'Report has expired'}), 410

    # Return JSON data that can be used for printing
    return jsonify({
        'format': 'json',
        'filename': f'osint_report_{inv_id}_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json',
        'data': report
    })


@bp.route('/api/reports/audit-history', methods=['GET'])
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
    for report_id, audit_entry in services.reports_audit_history.items():
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

        audit_entry_copy = audit_entry.copy()
        audit_entry_copy['days_ago'] = (end_date - entry_date).days
        audit_entry_copy['is_expired'] = report_id not in services.reports  # Check if still available

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


@bp.route('/api/reports/investigations/activity', methods=['GET'])
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

        # Parse enum filters - use INVESTIGATION_TYPE_MAP and PRIORITY_MAP from investigations.py
        from blueprints.investigations import INVESTIGATION_TYPE_MAP, PRIORITY_MAP
        investigation_type_enum = None
        if investigation_type_filter:
            investigation_type_enum = INVESTIGATION_TYPE_MAP.get(investigation_type_filter)

        priority_enum = None
        if priority_filter:
            priority_enum = PRIORITY_MAP.get(priority_filter)

        # Generate report from report_generator
        report = services.report_generator.generate_activity_report(
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
                'by_type': report.investigations_by_type if hasattr(report, 'investigations_by_type') else {},
                'by_priority': report.investigations_by_priority if hasattr(report, 'investigations_by_priority') else {},
                'by_status': report.investigations_by_status if hasattr(report, 'investigations_by_status') else {},
                'by_day': report.investigations_by_day if hasattr(report, 'investigations_by_day') else {}
            },
            'top_entities': {
                'investigators': report.top_investigators[:10] if hasattr(report, 'top_investigators') else report_data['investigators'][:10],
                'targets': report.top_targets[:20] if hasattr(report, 'top_targets') else []
            },
            'security_metrics': {
                'high_risk_investigations': report.high_risk_investigations if hasattr(report, 'high_risk_investigations') else 0,
                'classified_investigations': report.classified_investigations if hasattr(report, 'classified_investigations') else 0,
                'cross_border_investigations': report.cross_border_investigations if hasattr(report, 'cross_border_investigations') else 0
            },
            'operational_insights': {
                'peak_activity_hours': report.peak_activity_hours if hasattr(report, 'peak_activity_hours') else [],
                'busiest_days': report.busiest_days if hasattr(report, 'busiest_days') else [],
                'investigation_trends': report.investigation_trends if hasattr(report, 'investigation_trends') else {}
            }
        }

        # Include detailed data if requested
        if include_details and hasattr(report, 'investigators'):
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

            if hasattr(report, 'investigation_summaries'):
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

        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Investigation activity report failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/reports/investigations/activity/export', methods=['POST'])
def export_investigation_activity_report():
    """Export investigation activity report in specified format"""
    try:
        data = request.json
        export_format = data.get('format', 'json')

        # Generate report with same parameters
        time_range = data.get('time_range', 'last_30_days')
        start_date_str = data.get('start_date')
        end_date_str = data.get('end_date')
        investigator_filter = data.get('investigator')
        investigation_type_filter = data.get('type')
        priority_filter = data.get('priority')

        # Parse parameters
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

        from blueprints.investigations import INVESTIGATION_TYPE_MAP, PRIORITY_MAP
        investigation_type_enum = None
        if investigation_type_filter:
            investigation_type_enum = INVESTIGATION_TYPE_MAP.get(investigation_type_filter)

        priority_enum = None
        if priority_filter:
            priority_enum = PRIORITY_MAP.get(priority_filter)

        # Generate report
        report = services.report_generator.generate_activity_report(
            start_date=start_date,
            end_date=end_date,
            time_range=time_range_enum,
            investigator_filter=investigator_filter,
            investigation_type_filter=investigation_type_enum,
            priority_filter=priority_enum,
            include_detailed_summaries=True
        )

        # Export in requested format
        format_enum = ReportFormat.JSON
        if export_format == 'csv':
            format_enum = ReportFormat.CSV
        elif export_format == 'html':
            format_enum = ReportFormat.HTML

        exported_content = services.report_generator.export_report(report, format_enum)

        # Set appropriate content type and filename
        content_type = 'application/json'
        filename = f"investigation_activity_report_{report.report_id}.json"

        if export_format == 'csv':
            content_type = 'text/csv'
            filename = f"investigation_activity_report_{report.report_id}.csv"
        elif export_format == 'html':
            content_type = 'text/html'
            filename = f"investigation_activity_report_{report.report_id}.html"

        response = Response(
            response=exported_content,
            status=200,
            mimetype=content_type
        )
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"

        return response

    except Exception as e:
        logger.error(f"Report export failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/reports/investigators', methods=['GET'])
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
        report = services.report_generator.generate_activity_report(
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
        logger.error(f"Investigator summary failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/reports/targets', methods=['GET'])
def get_target_analysis():
    """Get analysis of investigation targets and patterns"""
    try:
        # Get query parameters
        time_range = request.args.get('time_range', 'last_30_days')
        limit = int(request.args.get('limit', 50))

        # Parse time range
        time_range_enum = getattr(TimeRange, time_range.upper().replace('_', '_'), TimeRange.LAST_30_DAYS)

        # Generate report for target data
        report = services.report_generator.generate_activity_report(
            time_range=time_range_enum,
            include_detailed_summaries=True
        )

        # Analyze target patterns
        from collections import defaultdict
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
            del analysis['risk_scores']

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
        logger.error(f"Target analysis failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/reports/professional/generate', methods=['POST'])
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
        investigation = services.orchestrator.get_investigation(investigation_id)
        if not investigation:
            return jsonify({'error': 'Investigation not found'}), 404

        # Generate professional report
        report_type_enum = ReportType(report_type)
        format_enum = ProfReportFormat(format_type)
        classification_enum = ClassificationLevel(classification)

        report = services.professional_report_generator.generate_report(
            investigation=investigation,
            report_type=report_type_enum,
            format_type=format_enum,
            classification=classification_enum,
            generated_by=generated_by
        )

        # Export report in requested format
        report_data = services.professional_report_generator.export_report(report, format_enum)

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
        logger.error(f"Professional report generation failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/reports/professional/<investigation_id>/download/<format_type>', methods=['GET'])
def download_professional_report(investigation_id, format_type):
    """Download professional report as file"""
    try:
        # Get investigation
        investigation = services.orchestrator.get_investigation(investigation_id)
        if not investigation:
            return jsonify({'error': 'Investigation not found'}), 404

        # Generate report
        report_type_enum = ReportType.COMPREHENSIVE
        format_enum = ProfReportFormat(format_type)
        classification_enum = ClassificationLevel.INTERNAL

        report = services.professional_report_generator.generate_report(
            investigation=investigation,
            report_type=report_type_enum,
            format_type=format_enum,
            classification=classification_enum
        )

        # Export report
        report_data = services.professional_report_generator.export_report(report, format_enum)

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
        logger.error(f"Report download failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500
