#!/usr/bin/env python3
"""
Graph Intelligence Algorithms

Provides centrality, community detection, path analysis,
similarity, anomaly detection, and influence propagation algorithms.
"""

from .centrality import (
    CentralityEngine,
    CentralityResult,
    AllCentralityResult,
    compute_centrality,
    get_top_central_nodes,
)

from .paths import (
    PathEngine,
    PathInfo,
    MultiPathResult,
    ReachabilityResult,
    find_shortest_path,
    find_all_paths,
    check_connection,
)

from .community import (
    CommunityEngine,
    CommunityResult,
    ComponentResult,
    KCoreResult,
    ClusteringResult,
    detect_communities,
    find_connected_components,
    get_dense_core,
)

from .similarity import (
    SimilarityEngine,
    SimilarityScore,
    SimilarityResult,
    BulkSimilarityResult,
    find_similar_entities,
    compute_pairwise_similarity,
)

from .anomaly import (
    AnomalyEngine,
    AnomalyScore,
    AnomalyResult,
    StructuralAnomalyResult,
    detect_anomalies,
    find_suspicious_entities,
)

__all__ = [
    # Centrality
    "CentralityEngine",
    "CentralityResult",
    "AllCentralityResult",
    "compute_centrality",
    "get_top_central_nodes",
    # Paths
    "PathEngine",
    "PathInfo",
    "MultiPathResult",
    "ReachabilityResult",
    "find_shortest_path",
    "find_all_paths",
    "check_connection",
    # Community
    "CommunityEngine",
    "CommunityResult",
    "ComponentResult",
    "KCoreResult",
    "ClusteringResult",
    "detect_communities",
    "find_connected_components",
    "get_dense_core",
    # Similarity
    "SimilarityEngine",
    "SimilarityScore",
    "SimilarityResult",
    "BulkSimilarityResult",
    "find_similar_entities",
    "compute_pairwise_similarity",
    # Anomaly Detection
    "AnomalyEngine",
    "AnomalyScore",
    "AnomalyResult",
    "StructuralAnomalyResult",
    "detect_anomalies",
    "find_suspicious_entities",
]
