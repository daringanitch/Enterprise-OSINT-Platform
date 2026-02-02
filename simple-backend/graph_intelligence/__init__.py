#!/usr/bin/env python3
"""
Graph Intelligence Engine

Palantir-inspired graph analytics for OSINT investigations.
Provides persistent graph storage, advanced algorithms, and pattern matching.
"""

from .models import (
    # Extended Entity Types
    ExtendedEntityType,
    ExtendedRelationshipType,

    # Core Graph Models
    GraphNode,
    GraphEdge,

    # Algorithm Results
    CentralityScores,
    CommunityInfo,
    PathResult,
    SimilarityResult,
    LinkPrediction,
    AnomalyResult,
    PropagationResult,

    # Query Models
    QueryResult,
    PatternMatch,

    # Visualization Models
    VisNode,
    VisEdge,
    GraphVisualization,

    # Graph Statistics
    GraphStatistics,

    # Configuration
    GraphConfig,
    GraphOperation,
)

from .neo4j_client import (
    GraphClient,
    create_graph_client,
)

# API (requires Flask)
try:
    from .api import (
        graph_bp,
        register_graph_api,
    )
except ImportError:
    graph_bp = None
    register_graph_api = None

__version__ = "1.0.0"
__all__ = [
    # Models
    "ExtendedEntityType",
    "ExtendedRelationshipType",
    "GraphNode",
    "GraphEdge",
    "CentralityScores",
    "CommunityInfo",
    "PathResult",
    "SimilarityResult",
    "LinkPrediction",
    "AnomalyResult",
    "PropagationResult",
    "QueryResult",
    "PatternMatch",
    "VisNode",
    "VisEdge",
    "GraphVisualization",
    "GraphStatistics",
    "GraphConfig",
    "GraphOperation",
    # Client
    "GraphClient",
    "create_graph_client",
    # API
    "graph_bp",
    "register_graph_api",
]
