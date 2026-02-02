#!/usr/bin/env python3
"""
Graph Intelligence REST API

Flask Blueprint providing REST endpoints for graph analytics.
Integrates with the main Flask app to expose graph capabilities.

Endpoints:
- /api/graph/centrality - Compute node centrality scores
- /api/graph/paths - Find paths between entities
- /api/graph/communities - Detect communities
- /api/graph/similarity - Find similar entities
- /api/graph/anomalies - Detect anomalies
- /api/graph/analyze - Full graph analysis
"""

import logging
from functools import wraps
from flask import Blueprint, request, jsonify, g
from typing import Any, Dict, List, Optional

from .models import GraphNode, GraphEdge, ExtendedEntityType, ExtendedRelationshipType
from .algorithms.centrality import CentralityEngine, compute_centrality
from .algorithms.paths import PathEngine, find_shortest_path, find_all_paths
from .algorithms.community import CommunityEngine, detect_communities
from .algorithms.similarity import SimilarityEngine, find_similar_entities
from .algorithms.anomaly import AnomalyEngine, detect_anomalies, find_suspicious_entities

logger = logging.getLogger(__name__)

# Create Blueprint
graph_bp = Blueprint('graph', __name__, url_prefix='/api/graph')


# =============================================================================
# HELPERS
# =============================================================================

def get_graph_data() -> tuple:
    """
    Get graph data from request or session.

    Returns:
        Tuple of (nodes, edges)
    """
    data = request.get_json() or {}

    nodes = []
    edges = []

    # Parse nodes from request
    for node_data in data.get('nodes', []):
        try:
            entity_type = ExtendedEntityType(node_data.get('entity_type', 'organization'))
        except ValueError:
            entity_type = ExtendedEntityType.ORGANIZATION

        node = GraphNode(
            entity_id=node_data.get('entity_id', ''),
            entity_type=entity_type,
            value=node_data.get('value', ''),
            risk_score=float(node_data.get('risk_score', 0)),
            confidence=float(node_data.get('confidence', 0.5)),
            tags=node_data.get('tags', []),
        )
        nodes.append(node)

    # Parse edges from request
    for edge_data in data.get('edges', []):
        try:
            rel_type = ExtendedRelationshipType(edge_data.get('relationship_type', 'associated_with'))
        except ValueError:
            rel_type = ExtendedRelationshipType.ASSOCIATED_WITH

        edge = GraphEdge(
            source_id=edge_data.get('source_id', ''),
            target_id=edge_data.get('target_id', ''),
            relationship_type=rel_type,
            weight=float(edge_data.get('weight', 1.0)),
            confidence=float(edge_data.get('confidence', 0.5)),
        )
        edges.append(edge)

    return nodes, edges


def api_response(data: Any, status: int = 200) -> tuple:
    """Create standardized API response."""
    return jsonify({
        'success': status < 400,
        'data': data,
    }), status


def error_response(message: str, status: int = 400) -> tuple:
    """Create standardized error response."""
    return jsonify({
        'success': False,
        'error': message,
    }), status


# =============================================================================
# CENTRALITY ENDPOINTS
# =============================================================================

@graph_bp.route('/centrality', methods=['POST'])
def compute_centrality_endpoint():
    """
    Compute centrality scores for nodes in the graph.

    Request body:
    {
        "nodes": [...],
        "edges": [...],
        "algorithm": "pagerank|betweenness|closeness|eigenvector|all",
        "top_k": 10
    }

    Returns:
        Centrality scores for nodes
    """
    try:
        nodes, edges = get_graph_data()
        data = request.get_json() or {}

        if not nodes:
            return error_response("No nodes provided")

        algorithm = data.get('algorithm', 'pagerank')
        top_k = int(data.get('top_k', 10))

        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        if algorithm == 'all':
            result = engine.compute_all_centrality()
            return api_response(result.to_dict())
        elif algorithm == 'pagerank':
            result = engine.pagerank()
        elif algorithm == 'betweenness':
            result = engine.betweenness_centrality()
        elif algorithm == 'closeness':
            result = engine.closeness_centrality()
        elif algorithm == 'eigenvector':
            result = engine.eigenvector_centrality()
        elif algorithm == 'degree':
            result = engine.degree_centrality()
        else:
            return error_response(f"Unknown algorithm: {algorithm}")

        return api_response({
            'algorithm': algorithm,
            'top_nodes': result.top_nodes[:top_k],
            'computation_time_ms': result.computation_time_ms,
        })

    except Exception as e:
        logger.exception("Error computing centrality")
        return error_response(str(e), 500)


@graph_bp.route('/centrality/<entity_id>', methods=['POST'])
def get_entity_centrality(entity_id: str):
    """
    Get centrality scores for a specific entity.

    Request body:
    {
        "nodes": [...],
        "edges": [...]
    }

    Returns:
        All centrality scores for the entity
    """
    try:
        nodes, edges = get_graph_data()

        if not nodes:
            return error_response("No nodes provided")

        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.compute_all_centrality()

        # Find entity in results
        entity_scores = {}
        for algo, scores in result.scores.items():
            entity_scores[algo] = scores.get(entity_id, 0)

        return api_response({
            'entity_id': entity_id,
            'centrality_scores': entity_scores,
        })

    except Exception as e:
        logger.exception("Error getting entity centrality")
        return error_response(str(e), 500)


# =============================================================================
# PATH ENDPOINTS
# =============================================================================

@graph_bp.route('/paths/shortest', methods=['POST'])
def find_shortest_path_endpoint():
    """
    Find shortest path between two entities.

    Request body:
    {
        "nodes": [...],
        "edges": [...],
        "source_id": "entity1",
        "target_id": "entity2",
        "max_depth": 10
    }

    Returns:
        Shortest path information
    """
    try:
        nodes, edges = get_graph_data()
        data = request.get_json() or {}

        source_id = data.get('source_id')
        target_id = data.get('target_id')
        max_depth = int(data.get('max_depth', 10))

        if not source_id or not target_id:
            return error_response("source_id and target_id are required")

        if not nodes:
            return error_response("No nodes provided")

        engine = PathEngine()
        engine.build_graph(nodes, edges)

        result = engine.shortest_path(source_id, target_id, max_depth=max_depth)

        return api_response(result.to_dict())

    except Exception as e:
        logger.exception("Error finding shortest path")
        return error_response(str(e), 500)


@graph_bp.route('/paths/all', methods=['POST'])
def find_all_paths_endpoint():
    """
    Find all paths between two entities.

    Request body:
    {
        "nodes": [...],
        "edges": [...],
        "source_id": "entity1",
        "target_id": "entity2",
        "max_depth": 5,
        "max_paths": 10
    }

    Returns:
        All paths found
    """
    try:
        nodes, edges = get_graph_data()
        data = request.get_json() or {}

        source_id = data.get('source_id')
        target_id = data.get('target_id')
        max_depth = int(data.get('max_depth', 5))
        max_paths = int(data.get('max_paths', 10))

        if not source_id or not target_id:
            return error_response("source_id and target_id are required")

        if not nodes:
            return error_response("No nodes provided")

        engine = PathEngine()
        engine.build_graph(nodes, edges)

        result = engine.all_paths(source_id, target_id, max_depth=max_depth, max_paths=max_paths)

        return api_response(result.to_dict())

    except Exception as e:
        logger.exception("Error finding all paths")
        return error_response(str(e), 500)


@graph_bp.route('/paths/reachable', methods=['POST'])
def find_reachable_endpoint():
    """
    Find all entities reachable from a source within N hops.

    Request body:
    {
        "nodes": [...],
        "edges": [...],
        "source_id": "entity1",
        "max_hops": 3
    }

    Returns:
        Reachable entities by hop distance
    """
    try:
        nodes, edges = get_graph_data()
        data = request.get_json() or {}

        source_id = data.get('source_id')
        max_hops = int(data.get('max_hops', 3))

        if not source_id:
            return error_response("source_id is required")

        if not nodes:
            return error_response("No nodes provided")

        engine = PathEngine()
        engine.build_graph(nodes, edges)

        result = engine.reachability(source_id, max_hops=max_hops)

        return api_response(result.to_dict())

    except Exception as e:
        logger.exception("Error finding reachable entities")
        return error_response(str(e), 500)


# =============================================================================
# COMMUNITY ENDPOINTS
# =============================================================================

@graph_bp.route('/communities', methods=['POST'])
def detect_communities_endpoint():
    """
    Detect communities in the graph.

    Request body:
    {
        "nodes": [...],
        "edges": [...],
        "algorithm": "louvain|label_propagation",
        "resolution": 1.0
    }

    Returns:
        Detected communities
    """
    try:
        nodes, edges = get_graph_data()
        data = request.get_json() or {}

        algorithm = data.get('algorithm', 'louvain')
        resolution = float(data.get('resolution', 1.0))

        if not nodes:
            return error_response("No nodes provided")

        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        if algorithm == 'louvain':
            result = engine.louvain(resolution=resolution)
        elif algorithm == 'label_propagation':
            result = engine.label_propagation()
        else:
            return error_response(f"Unknown algorithm: {algorithm}")

        return api_response(result.to_dict())

    except Exception as e:
        logger.exception("Error detecting communities")
        return error_response(str(e), 500)


@graph_bp.route('/communities/components', methods=['POST'])
def find_components_endpoint():
    """
    Find connected components in the graph.

    Request body:
    {
        "nodes": [...],
        "edges": [...],
        "strong": false
    }

    Returns:
        Connected components
    """
    try:
        nodes, edges = get_graph_data()
        data = request.get_json() or {}

        strong = data.get('strong', False)

        if not nodes:
            return error_response("No nodes provided")

        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        if strong:
            result = engine.strongly_connected_components()
        else:
            result = engine.weakly_connected_components()

        return api_response(result.to_dict())

    except Exception as e:
        logger.exception("Error finding components")
        return error_response(str(e), 500)


@graph_bp.route('/communities/kcore', methods=['POST'])
def find_kcore_endpoint():
    """
    Find k-core decomposition of the graph.

    Request body:
    {
        "nodes": [...],
        "edges": [...],
        "k": 2
    }

    Returns:
        K-core decomposition
    """
    try:
        nodes, edges = get_graph_data()
        data = request.get_json() or {}

        k = int(data.get('k', 2))

        if not nodes:
            return error_response("No nodes provided")

        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.k_core_decomposition()
        k_core_nodes = engine.get_k_core(k)

        return api_response({
            'k': k,
            'max_k': result.max_k,
            'degeneracy': result.degeneracy,
            'k_core_nodes': k_core_nodes,
            'k_core_size': len(k_core_nodes),
        })

    except Exception as e:
        logger.exception("Error finding k-core")
        return error_response(str(e), 500)


# =============================================================================
# SIMILARITY ENDPOINTS
# =============================================================================

@graph_bp.route('/similarity', methods=['POST'])
def find_similar_endpoint():
    """
    Find entities similar to a given entity.

    Request body:
    {
        "nodes": [...],
        "edges": [...],
        "entity_id": "target_entity",
        "method": "jaccard|adamic_adar|cosine|simrank",
        "top_k": 10,
        "same_type_only": false
    }

    Returns:
        Similar entities ranked by similarity
    """
    try:
        nodes, edges = get_graph_data()
        data = request.get_json() or {}

        entity_id = data.get('entity_id')
        method = data.get('method', 'jaccard')
        top_k = int(data.get('top_k', 10))
        same_type_only = data.get('same_type_only', False)

        if not entity_id:
            return error_response("entity_id is required")

        if not nodes:
            return error_response("No nodes provided")

        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        result = engine.find_similar(
            entity_id,
            method=method,
            top_k=top_k,
            same_type_only=same_type_only
        )

        return api_response(result.to_dict())

    except Exception as e:
        logger.exception("Error finding similar entities")
        return error_response(str(e), 500)


@graph_bp.route('/similarity/bulk', methods=['POST'])
def bulk_similarity_endpoint():
    """
    Compute pairwise similarity for all entities.

    Request body:
    {
        "nodes": [...],
        "edges": [...],
        "method": "jaccard|adamic_adar|cosine",
        "min_score": 0.1,
        "same_type_only": false
    }

    Returns:
        All similar pairs above threshold
    """
    try:
        nodes, edges = get_graph_data()
        data = request.get_json() or {}

        method = data.get('method', 'jaccard')
        min_score = float(data.get('min_score', 0.1))
        same_type_only = data.get('same_type_only', False)

        if not nodes:
            return error_response("No nodes provided")

        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        result = engine.compute_all_pairs(
            method=method,
            min_score=min_score,
            same_type_only=same_type_only
        )

        return api_response(result.to_dict())

    except Exception as e:
        logger.exception("Error computing bulk similarity")
        return error_response(str(e), 500)


# =============================================================================
# ANOMALY ENDPOINTS
# =============================================================================

@graph_bp.route('/anomalies', methods=['POST'])
def detect_anomalies_endpoint():
    """
    Detect anomalies in the graph.

    Request body:
    {
        "nodes": [...],
        "edges": [...],
        "methods": ["degree", "clustering", "bridge", "hub", "star_pattern"],
        "z_threshold": 2.0
    }

    Returns:
        Detected anomalies by method
    """
    try:
        nodes, edges = get_graph_data()
        data = request.get_json() or {}

        methods = data.get('methods', ['degree', 'clustering', 'bridge', 'hub'])
        z_threshold = float(data.get('z_threshold', 2.0))

        if not nodes:
            return error_response("No nodes provided")

        results = detect_anomalies(nodes, edges, methods=methods, z_threshold=z_threshold)

        return api_response({
            method: result.to_dict() for method, result in results.items()
        })

    except Exception as e:
        logger.exception("Error detecting anomalies")
        return error_response(str(e), 500)


@graph_bp.route('/anomalies/suspicious', methods=['POST'])
def find_suspicious_endpoint():
    """
    Find the most suspicious entities.

    Request body:
    {
        "nodes": [...],
        "edges": [...],
        "top_k": 20
    }

    Returns:
        Most suspicious entities across all detection methods
    """
    try:
        nodes, edges = get_graph_data()
        data = request.get_json() or {}

        top_k = int(data.get('top_k', 20))

        if not nodes:
            return error_response("No nodes provided")

        suspicious = find_suspicious_entities(nodes, edges, top_k=top_k)

        return api_response({
            'suspicious_count': len(suspicious),
            'entities': [s.to_dict() for s in suspicious],
        })

    except Exception as e:
        logger.exception("Error finding suspicious entities")
        return error_response(str(e), 500)


# =============================================================================
# FULL ANALYSIS ENDPOINT
# =============================================================================

@graph_bp.route('/analyze', methods=['POST'])
def full_analysis_endpoint():
    """
    Run comprehensive graph analysis.

    Request body:
    {
        "nodes": [...],
        "edges": [...],
        "include": {
            "centrality": true,
            "communities": true,
            "anomalies": true
        }
    }

    Returns:
        Complete analysis results
    """
    try:
        nodes, edges = get_graph_data()
        data = request.get_json() or {}

        include = data.get('include', {
            'centrality': True,
            'communities': True,
            'anomalies': True,
        })

        if not nodes:
            return error_response("No nodes provided")

        results = {
            'node_count': len(nodes),
            'edge_count': len(edges),
        }

        # Centrality analysis
        if include.get('centrality', True):
            engine = CentralityEngine()
            engine.build_graph(nodes, edges)
            centrality = engine.compute_all_centrality()
            results['centrality'] = {
                'top_pagerank': centrality.top_nodes[:10],
                'computation_time_ms': centrality.computation_time_ms,
            }

        # Community detection
        if include.get('communities', True):
            engine = CommunityEngine()
            engine.build_graph(nodes, edges)
            communities = engine.louvain()
            results['communities'] = {
                'count': communities.community_count,
                'modularity': communities.modularity,
                'largest_size': max((c.size for c in communities.communities), default=0),
            }

        # Anomaly detection
        if include.get('anomalies', True):
            engine = AnomalyEngine()
            engine.build_graph(nodes, edges)
            all_anomalies = engine.detect_all_anomalies()
            results['anomalies'] = {
                'total': all_anomalies.to_dict()['total_anomalies'],
                'degree_anomalies': len(all_anomalies.degree_anomalies),
                'bridge_nodes': len(all_anomalies.bridge_anomalies),
                'hub_authorities': len(all_anomalies.hub_anomalies),
            }

        return api_response(results)

    except Exception as e:
        logger.exception("Error in full analysis")
        return error_response(str(e), 500)


# =============================================================================
# HEALTH CHECK
# =============================================================================

@graph_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for graph API."""
    return api_response({
        'status': 'healthy',
        'service': 'graph-intelligence',
        'version': '1.0.0',
    })


# =============================================================================
# REGISTRATION HELPER
# =============================================================================

def register_graph_api(app):
    """
    Register the graph API blueprint with a Flask app.

    Args:
        app: Flask application instance
    """
    app.register_blueprint(graph_bp)
    logger.info("Graph Intelligence API registered at /api/graph")
