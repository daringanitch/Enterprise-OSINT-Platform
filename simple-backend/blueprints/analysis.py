#!/usr/bin/env python3
"""
Blueprint for advanced analysis endpoints
"""
from flask import Blueprint, jsonify, request
from shared import services
from datetime import datetime
import logging

from blueprints.auth import require_auth
from advanced_analysis import MITREMapper, RiskScoringEngine, ExecutiveSummaryGenerator, TrendAnalyzer, ChartDataGenerator

logger = logging.getLogger(__name__)

bp = Blueprint('analysis', __name__)


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
                }
            ],
            'tactic_count': 1,
            'technique_count': 1
        },
        'executive_summary': {
            'overview': f'Investigation of {target} shows moderate risk',
            'key_findings': ['Some findings here'],
            'recommendations': ['Monitor continuously']
        }
    }


@bp.route('/api/analysis/advanced', methods=['POST'])
@require_auth
def perform_advanced_analysis():
    """Perform advanced analysis on provided findings data"""
    if not services.ADVANCED_ANALYSIS_AVAILABLE:
        return jsonify({'error': 'Advanced analysis not available'}), 503

    data = request.json or {}
    target = data.get('target', 'Unknown')
    findings = data.get('findings', {})
    correlation_results = data.get('correlation_results')

    if not findings:
        return jsonify({'error': 'No findings data provided'}), 400

    try:
        result = services.advanced_analysis_engine.analyze(target, findings, correlation_results)
        return jsonify({
            'success': True,
            'analysis': result
        })

    except Exception as e:
        logger.error(f"Advanced analysis error: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/analysis/mitre-mapping', methods=['POST'])
@require_auth
def get_mitre_mapping():
    """Map findings to MITRE ATT&CK techniques"""
    if not services.ADVANCED_ANALYSIS_AVAILABLE:
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
        logger.error(f"MITRE mapping error: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/analysis/risk-score', methods=['POST'])
@require_auth
def calculate_risk_score():
    """Calculate comprehensive risk score"""
    if not services.ADVANCED_ANALYSIS_AVAILABLE:
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
        logger.error(f"Risk scoring error: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/analysis/executive-summary', methods=['POST'])
@require_auth
def generate_executive_summary():
    """Generate executive summary from analysis results"""
    if not services.ADVANCED_ANALYSIS_AVAILABLE:
        return jsonify({'error': 'Advanced analysis not available'}), 503

    data = request.json or {}
    target = data.get('target', 'Unknown')
    findings = data.get('findings', {})

    try:
        # Calculate risk score if not provided
        risk_data = data.get('risk_score')
        if risk_data:
            from advanced_analysis import RiskScore
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
        logger.error(f"Executive summary error: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/analysis/trends', methods=['POST'])
@require_auth
def analyze_trends():
    """Analyze trends from timeline data"""
    if not services.ADVANCED_ANALYSIS_AVAILABLE:
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
        logger.error(f"Trend analysis error: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/analysis/charts', methods=['POST'])
@require_auth
def generate_chart_data():
    """Generate chart data for visualization"""
    if not services.ADVANCED_ANALYSIS_AVAILABLE:
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
        logger.error(f"Chart generation error: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/mitre/techniques', methods=['GET'])
@require_auth
def get_mitre_techniques():
    """Get list of supported MITRE ATT&CK techniques"""
    if not services.ADVANCED_ANALYSIS_AVAILABLE:
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
