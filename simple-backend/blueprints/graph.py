#!/usr/bin/env python3
"""
Blueprint for graph intelligence endpoints
"""
from flask import Blueprint, jsonify, request
from shared import services
from datetime import datetime
import logging

from blueprints.auth import require_auth
from graph_intelligence.algorithms import (
    CentralityEngine, PathEngine, CommunityEngine,
    SimilarityEngine, AnomalyEngine, InfluenceEngine
)

logger = logging.getLogger(__name__)

bp = Blueprint('graph', __name__)


@bp.route('/api/investigations/<investigation_id>/graph/sync', methods=['POST'])
@require_auth
def sync_investigation_to_graph(investigation_id):
    """Sync investigation data to the graph intelligence system"""
    if not services.GRAPH_INTELLIGENCE_AVAILABLE or not services.graph_sync:
        return jsonify({
            'error': 'Graph Intelligence not available',
            'message': 'Graph Intelligence module is not installed or failed to initialize'
        }), 503

    # Get investigation data
    if services.mode_manager.is_demo_mode():
        demo_inv = services.demo_provider.get_demo_investigation(investigation_id)
        if not demo_inv:
            return jsonify({'error': 'Investigation not found'}), 404
        investigation_data = demo_inv
    else:
        investigation = services.orchestrator.get_investigation_status(investigation_id)
        if not investigation:
            return jsonify({'error': 'Investigation not found'}), 404

        # Build investigation data dict
        investigation_data = {
            'id': investigation_id,
            'target': getattr(investigation, 'target', ''),
            'correlation': getattr(investigation, 'correlation_results', {}),
            'mcp_results': getattr(investigation, 'mcp_results', {}),
            'findings': getattr(investigation, 'findings', {}),
        }

    try:
        # Extract and sync
        extraction, sync_result = services.graph_sync.sync_investigation(
            investigation_data,
            investigation_id
        )

        return jsonify({
            'investigation_id': investigation_id,
            'extraction': extraction.to_dict(),
            'sync': sync_result.to_dict(),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Graph sync error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Graph sync failed',
            'message': 'An internal error occurred. Check server logs.'
        }), 500


@bp.route('/api/investigations/<investigation_id>/graph/analyze', methods=['POST'])
@require_auth
def analyze_investigation_graph(investigation_id):
    """Run graph analysis on investigation data"""
    if not services.GRAPH_INTELLIGENCE_AVAILABLE:
        return jsonify({
            'error': 'Graph Intelligence not available',
            'message': 'Graph Intelligence module is not installed'
        }), 503

    # Parse options
    include_centrality = request.args.get('include_centrality', 'true').lower() == 'true'
    include_communities = request.args.get('include_communities', 'true').lower() == 'true'
    include_anomalies = request.args.get('include_anomalies', 'true').lower() == 'true'
    include_similarity = request.args.get('include_similarity', 'false').lower() == 'true'

    # Get investigation data
    if services.mode_manager.is_demo_mode():
        demo_inv = services.demo_provider.get_demo_investigation(investigation_id)
        if not demo_inv:
            return jsonify({'error': 'Investigation not found'}), 404
        investigation_data = demo_inv
    else:
        investigation = services.orchestrator.get_investigation_status(investigation_id)
        if not investigation:
            return jsonify({'error': 'Investigation not found'}), 404
        investigation_data = {
            'id': investigation_id,
            'correlation': getattr(investigation, 'correlation_results', {}),
        }

    try:
        # Extract entities to graph format
        extraction = services.graph_sync.extract_from_investigation(investigation_data, investigation_id)

        if not extraction.nodes:
            return jsonify({
                'investigation_id': investigation_id,
                'message': 'No entities found to analyze',
                'entities_found': 0,
                'timestamp': datetime.utcnow().isoformat()
            })

        results = {
            'investigation_id': investigation_id,
            'entities_analyzed': len(extraction.nodes),
            'relationships_analyzed': len(extraction.edges),
            'timestamp': datetime.utcnow().isoformat()
        }

        # Run centrality analysis
        if include_centrality:
            centrality_engine = CentralityEngine()
            centrality_engine.build_graph(extraction.nodes, extraction.edges)
            centrality_result = centrality_engine.compute_all_centrality()
            results['centrality'] = {
                'top_nodes': [
                    {'entity_id': eid, 'score': round(score, 4)}
                    for eid, score in centrality_result.top_by_composite[:10]
                ],
                'computation_time_ms': centrality_result.total_computation_time_ms
            }

        # Run community detection
        if include_communities:
            community_engine = CommunityEngine()
            community_engine.build_graph(extraction.nodes, extraction.edges)
            community_result = community_engine.louvain()
            results['communities'] = {
                'count': community_result.community_count,
                'modularity': round(community_result.modularity, 4),
                'communities': [c.to_dict() for c in community_result.communities[:5]]
            }

        # Run anomaly detection
        if include_anomalies:
            anomaly_engine = AnomalyEngine()
            anomaly_engine.build_graph(extraction.nodes, extraction.edges)
            anomaly_result = anomaly_engine.detect_all_anomalies()
            results['anomalies'] = {
                'total': anomaly_result.to_dict()['total_anomalies'],
                'degree_anomalies': [a.to_dict() for a in anomaly_result.degree_anomalies[:5]],
                'bridge_nodes': [a.to_dict() for a in anomaly_result.bridge_anomalies[:5]],
                'hub_authorities': [a.to_dict() for a in anomaly_result.hub_anomalies[:5]]
            }

        # Run similarity analysis
        if include_similarity and len(extraction.nodes) > 1:
            similarity_engine = SimilarityEngine()
            similarity_engine.build_graph(extraction.nodes, extraction.edges)
            bulk_result = similarity_engine.compute_all_pairs(method='jaccard', min_score=0.3)
            results['similarity'] = {
                'similar_pairs': bulk_result.pair_count,
                'top_pairs': [p.to_dict() for p in bulk_result.pairs[:10]]
            }

        return jsonify(results)

    except Exception as e:
        logger.error(f"Graph analysis error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Graph analysis failed',
            'message': 'An internal error occurred. Check server logs.'
        }), 500


@bp.route('/api/investigations/<investigation_id>/graph/paths', methods=['POST'])
@require_auth
def find_investigation_paths(investigation_id):
    """Find paths between entities in an investigation"""
    if not services.GRAPH_INTELLIGENCE_AVAILABLE:
        return jsonify({'error': 'Graph Intelligence not available'}), 503

    data = request.get_json() or {}
    source_id = data.get('source_id')
    target_id = data.get('target_id')
    max_depth = int(data.get('max_depth', 5))

    if not source_id or not target_id:
        return jsonify({'error': 'source_id and target_id are required'}), 400

    # Get investigation data
    if services.mode_manager.is_demo_mode():
        demo_inv = services.demo_provider.get_demo_investigation(investigation_id)
        if not demo_inv:
            return jsonify({'error': 'Investigation not found'}), 404
        investigation_data = demo_inv
    else:
        investigation = services.orchestrator.get_investigation_status(investigation_id)
        if not investigation:
            return jsonify({'error': 'Investigation not found'}), 404
        investigation_data = {
            'correlation': getattr(investigation, 'correlation_results', {}),
        }

    try:
        extraction = services.graph_sync.extract_from_investigation(investigation_data, investigation_id)

        path_engine = PathEngine()
        path_engine.build_graph(extraction.nodes, extraction.edges)

        result = path_engine.shortest_path(source_id, target_id, max_depth=max_depth)

        return jsonify({
            'investigation_id': investigation_id,
            'path': result.to_dict(),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Path finding error: {str(e)}", exc_info=True)
        return jsonify({'error': 'Path finding failed', 'message': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/investigations/<investigation_id>/graph/blast-radius', methods=['POST'])
@require_auth
def analyze_blast_radius(investigation_id):
    """Analyze the blast radius if an entity is compromised"""
    if not services.GRAPH_INTELLIGENCE_AVAILABLE:
        return jsonify({'error': 'Graph Intelligence not available'}), 503

    data = request.get_json() or {}
    entity_id = data.get('entity_id')
    max_hops = int(data.get('max_hops', 3))

    if not entity_id:
        return jsonify({'error': 'entity_id is required'}), 400

    # Get investigation data
    if services.mode_manager.is_demo_mode():
        demo_inv = services.demo_provider.get_demo_investigation(investigation_id)
        if not demo_inv:
            return jsonify({'error': 'Investigation not found'}), 404
        investigation_data = demo_inv
    else:
        investigation = services.orchestrator.get_investigation_status(investigation_id)
        if not investigation:
            return jsonify({'error': 'Investigation not found'}), 404
        investigation_data = {
            'correlation': getattr(investigation, 'correlation_results', {}),
        }

    try:
        extraction = services.graph_sync.extract_from_investigation(investigation_data, investigation_id)

        influence_engine = InfluenceEngine()
        influence_engine.build_graph(extraction.nodes, extraction.edges)

        result = influence_engine.blast_radius(entity_id, max_hops=max_hops)

        return jsonify({
            'investigation_id': investigation_id,
            'blast_radius': result.to_dict(),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Blast radius analysis error: {str(e)}", exc_info=True)
        return jsonify({'error': 'Blast radius analysis failed', 'message': 'An internal error occurred. Check server logs.'}), 500


@bp.route('/api/graph/status', methods=['GET'])
def graph_status():
    """Get Graph Intelligence system status"""
    return jsonify({
        'available': services.GRAPH_INTELLIGENCE_AVAILABLE,
        'sync_enabled': services.graph_sync is not None,
        'algorithms': [
            'centrality', 'paths', 'community',
            'similarity', 'anomaly', 'influence'
        ] if services.GRAPH_INTELLIGENCE_AVAILABLE else [],
        'timestamp': datetime.utcnow().isoformat()
    })
