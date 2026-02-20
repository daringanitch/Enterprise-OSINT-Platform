#!/usr/bin/env python3
"""
Blueprint for compliance framework endpoints
"""
from flask import Blueprint, jsonify, request
from shared import services
from datetime import datetime, timedelta
import logging

from compliance_framework import ComplianceFramework

logger = logging.getLogger(__name__)

bp = Blueprint('compliance', __name__)


@bp.route('/api/compliance/frameworks', methods=['GET'])
def get_compliance_frameworks():
    """Get available compliance frameworks and their details"""
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


@bp.route('/api/compliance/assessment', methods=['POST'])
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
        if services.mode_manager.is_demo_mode():
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
        assessment = services.compliance_engine.assess_compliance(
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
                'remediation_actions': assessment.remediation_actions[:10],
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
        logger.error(f"Compliance assessment failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/compliance/investigations/<inv_id>/reports', methods=['GET'])
def get_investigation_compliance_reports(inv_id):
    """Get compliance reports for specific investigation"""
    # Handle demo mode
    if services.mode_manager.is_demo_mode():
        demo_inv = services.demo_provider.get_demo_investigation(inv_id)
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

    investigation = services.orchestrator.get_investigation(inv_id)

    if not investigation:
        return jsonify({'error': 'Investigation not found'}), 404

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


@bp.route('/api/compliance/audit-trail', methods=['GET'])
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

            audit_data = services.compliance_engine.processing_logger.generate_compliance_report(
                framework_enum, start_date, end_date
            )
        else:
            # Get all audit entries
            audit_entries = services.compliance_engine.processing_logger.get_audit_trail()

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
                'entries': filtered_entries[-100:],
                'frameworks_assessed': list(set(
                    entry.get('framework') for entry in filtered_entries
                    if entry.get('framework')
                ))
            }

        return jsonify(audit_data)

    except Exception as e:
        logger.error(f"Audit trail retrieval failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/compliance/dashboard', methods=['GET'])
def get_compliance_dashboard():
    """Get compliance dashboard overview"""
    try:
        # Get recent investigations
        active_investigations = services.orchestrator.get_active_investigations()

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
        recent_audit = services.compliance_engine.processing_logger.get_audit_trail()[-10:] if services.compliance_engine.processing_logger.processing_log else []

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
        logger.error(f"Compliance dashboard failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500
