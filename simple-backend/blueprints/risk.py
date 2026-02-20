#!/usr/bin/env python3
"""
Blueprint for risk assessment endpoints
"""
from flask import Blueprint, jsonify, request
from shared import services
from datetime import datetime
import logging

from problem_json import InvestigationNotFoundError

logger = logging.getLogger(__name__)

bp = Blueprint('risk', __name__)


@bp.route('/api/risk/assess', methods=['POST'])
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
        risk_assessment = services.orchestrator.risk_engine.assess_risk(
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
        logger.error(f"Standalone risk assessment failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/risk/investigations/<inv_id>', methods=['GET'])
def get_investigation_risk_assessment(inv_id):
    """Get risk assessment for specific investigation"""
    # Handle demo mode
    if services.mode_manager.is_demo_mode():
        demo_inv = services.demo_provider.get_demo_investigation(inv_id)
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

    investigation = services.orchestrator.get_investigation(inv_id)

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


@bp.route('/api/risk/correlate', methods=['POST'])
def correlate_intelligence_sources():
    """Correlate intelligence across multiple sources for threat analysis"""
    try:
        data = request.json

        social_intel = data.get('social_intelligence', {})
        infrastructure_intel = data.get('infrastructure_intelligence', {})
        threat_intel = data.get('threat_intelligence', {})
        behavioral_intel = data.get('behavioral_intelligence', {})

        # Use the correlation engine to find relationships
        indicators = services.orchestrator.risk_engine.correlation_engine.correlate_intelligence(
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
        logger.error(f"Intelligence correlation failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/risk/trends/<target_id>', methods=['GET'])
def get_risk_trends(target_id):
    """Get risk trend analysis for specific target"""
    try:
        # Get historical risk assessments from the risk engine
        historical_assessments = services.orchestrator.risk_engine.risk_history.get(target_id, [])

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
        logger.error(f"Risk trend analysis failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500
