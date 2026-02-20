#!/usr/bin/env python3
"""
Blueprint for intelligence gathering and correlation endpoints
"""
from flask import Blueprint, jsonify, request
from shared import services
from datetime import datetime
import logging
import asyncio

from blueprints.auth import require_auth
from intelligence_correlation import IntelligenceCorrelator, EntityType, RelationshipType

logger = logging.getLogger(__name__)

bp = Blueprint('intelligence', __name__)


@bp.route('/api/intelligence/sources', methods=['GET'])
@require_auth
def get_intelligence_sources():
    """Get list of available expanded intelligence sources"""
    if not services.EXPANDED_SOURCES_AVAILABLE:
        return jsonify({
            'available': False,
            'message': 'Expanded data sources not available',
            'sources': []
        })

    sources = services.expanded_data_manager.get_available_sources()
    return jsonify({
        'available': True,
        'sources': sources,
        'total_sources': len(sources)
    })


@bp.route('/api/intelligence/gather', methods=['POST'])
@require_auth
def gather_expanded_intelligence():
    """Gather intelligence from expanded data sources"""
    if not services.EXPANDED_SOURCES_AVAILABLE:
        return jsonify({
            'error': 'Expanded data sources not available'
        }), 503

    data = request.json or {}
    target = data.get('target', '').strip()
    sources = data.get('sources')  # None = all sources

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    # Validate target format
    if services.VALIDATION_ENABLED:
        try:
            from validators import validate_target_format
            target = validate_target_format(target)
        except Exception as e:
            logger.warning(f"Target validation failed: {str(e)}", exc_info=True)
            return jsonify({'error': 'Invalid target format'}), 400

    try:
        # Run async gathering
        async def gather():
            return await services.expanded_data_manager.gather_all(target, sources)

        # Execute async function
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
        summary = services.expanded_data_manager.get_aggregated_summary(results)

        return jsonify({
            'target': target,
            'results': response_data,
            'summary': summary,
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"Expanded intelligence gathering error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Intelligence gathering failed',
            'message': 'An internal error occurred. Check server logs.'
        }), 500


@bp.route('/api/intelligence/source/<source_name>', methods=['POST'])
@require_auth
def gather_from_source(source_name):
    """Gather intelligence from a specific source"""
    if not services.EXPANDED_SOURCES_AVAILABLE:
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
            return await services.expanded_data_manager.gather_all(target, [source_name])

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
        logger.error(f"Source {source_name} gathering error: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/correlation/analyze', methods=['POST'])
@require_auth
def correlate_intelligence():
    """Perform entity extraction and correlation on provided data"""
    if not services.CORRELATION_AVAILABLE:
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
        logger.error(f"Correlation error: {str(e)}", exc_info=True)
        return jsonify({'error': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/correlation/entity-types', methods=['GET'])
@require_auth
def get_entity_types():
    """Get list of supported entity types for correlation"""
    if not services.CORRELATION_AVAILABLE:
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


@bp.route('/api/investigations/<investigation_id>/correlation', methods=['GET'])
@require_auth
def get_investigation_correlation(investigation_id):
    """Get correlation results for a specific investigation"""
    # Check demo mode
    if services.mode_manager.is_demo_mode():
        demo_inv = services.demo_provider.get_demo_investigation(investigation_id)
        if demo_inv:
            # Generate sample correlation for demo
            from blueprints.analysis import _generate_demo_correlation
            return jsonify({
                'investigation_id': investigation_id,
                'correlation': _generate_demo_correlation(demo_inv),
                'timestamp': datetime.utcnow().isoformat()
            })
        return jsonify({'error': 'Investigation not found'}), 404

    # Check active investigations
    investigation = services.orchestrator.get_investigation_status(investigation_id)
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


@bp.route('/api/investigations/<investigation_id>/entities', methods=['GET'])
@require_auth
def get_investigation_entities(investigation_id):
    """Get extracted entities for a specific investigation"""
    entity_type = request.args.get('type')
    min_confidence = float(request.args.get('min_confidence', 0))

    # Check demo mode
    if services.mode_manager.is_demo_mode():
        demo_inv = services.demo_provider.get_demo_investigation(investigation_id)
        if demo_inv:
            from blueprints.analysis import _generate_demo_entities
            entities = _generate_demo_entities(demo_inv, entity_type, min_confidence)
            return jsonify({
                'investigation_id': investigation_id,
                'entities': entities,
                'count': len(entities),
                'timestamp': datetime.utcnow().isoformat()
            })
        return jsonify({'error': 'Investigation not found'}), 404

    investigation = services.orchestrator.get_investigation_status(investigation_id)
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


@bp.route('/api/investigations/<investigation_id>/timeline', methods=['GET'])
@require_auth
def get_investigation_timeline(investigation_id):
    """Get reconstructed timeline for a specific investigation"""
    severity = request.args.get('severity')
    limit = int(request.args.get('limit', 100))

    # Check demo mode
    if services.mode_manager.is_demo_mode():
        demo_inv = services.demo_provider.get_demo_investigation(investigation_id)
        if demo_inv:
            from blueprints.analysis import _generate_demo_timeline
            timeline = _generate_demo_timeline(demo_inv, severity, limit)
            return jsonify({
                'investigation_id': investigation_id,
                'timeline': timeline,
                'count': len(timeline),
                'timestamp': datetime.utcnow().isoformat()
            })
        return jsonify({'error': 'Investigation not found'}), 404

    investigation = services.orchestrator.get_investigation_status(investigation_id)
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


@bp.route('/api/investigations/<investigation_id>/relationships', methods=['GET'])
@require_auth
def get_investigation_relationships(investigation_id):
    """Get entity relationships for a specific investigation"""
    rel_type = request.args.get('type')
    entity_id = request.args.get('entity_id')

    # Check demo mode
    if services.mode_manager.is_demo_mode():
        demo_inv = services.demo_provider.get_demo_investigation(investigation_id)
        if demo_inv:
            from blueprints.analysis import _generate_demo_relationships
            relationships = _generate_demo_relationships(demo_inv, rel_type, entity_id)
            return jsonify({
                'investigation_id': investigation_id,
                'relationships': relationships,
                'count': len(relationships),
                'timestamp': datetime.utcnow().isoformat()
            })
        return jsonify({'error': 'Investigation not found'}), 404

    investigation = services.orchestrator.get_investigation_status(investigation_id)
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
