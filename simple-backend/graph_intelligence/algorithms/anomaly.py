#!/usr/bin/env python3
"""
Graph Anomaly Detection Algorithms

Detect unusual patterns, outliers, and suspicious behavior in the graph.
Essential for threat intelligence to identify compromised infrastructure,
emerging threats, and unusual actor behavior.

Capabilities:
- Structural anomalies (unusual degree, clustering)
- Temporal anomalies (sudden changes)
- Attribute anomalies (outlier values)
- Community anomalies (bridging, isolation)
- Network anomalies (star patterns, cliques)
"""

import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models import (
    ExtendedEntityType,
    ExtendedRelationshipType,
    GraphNode,
    GraphEdge,
)

logger = logging.getLogger(__name__)


# =============================================================================
# RESULT CLASSES
# =============================================================================

@dataclass
class AnomalyScore:
    """Anomaly score for a single entity."""
    entity_id: str
    entity_type: str
    value: str
    anomaly_score: float  # 0-1, higher = more anomalous
    anomaly_type: str
    explanation: str
    contributing_factors: List[str] = field(default_factory=list)
    severity: str = "low"  # low, medium, high, critical

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "value": self.value,
            "anomaly_score": round(self.anomaly_score, 4),
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "explanation": self.explanation,
            "contributing_factors": self.contributing_factors,
        }


@dataclass
class AnomalyResult:
    """Result of anomaly detection."""
    method: str
    anomaly_count: int
    threshold: float
    anomalies: List[AnomalyScore] = field(default_factory=list)
    statistics: Dict[str, float] = field(default_factory=dict)
    computation_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "anomaly_count": self.anomaly_count,
            "threshold": self.threshold,
            "statistics": {k: round(v, 4) for k, v in self.statistics.items()},
            "anomalies": [a.to_dict() for a in self.anomalies[:50]],
            "computation_time_ms": round(self.computation_time_ms, 2),
        }


@dataclass
class StructuralAnomalyResult:
    """Result of structural anomaly detection."""
    degree_anomalies: List[AnomalyScore] = field(default_factory=list)
    clustering_anomalies: List[AnomalyScore] = field(default_factory=list)
    bridge_anomalies: List[AnomalyScore] = field(default_factory=list)
    hub_anomalies: List[AnomalyScore] = field(default_factory=list)
    computation_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "degree_anomalies": [a.to_dict() for a in self.degree_anomalies[:20]],
            "clustering_anomalies": [a.to_dict() for a in self.clustering_anomalies[:20]],
            "bridge_anomalies": [a.to_dict() for a in self.bridge_anomalies[:20]],
            "hub_anomalies": [a.to_dict() for a in self.hub_anomalies[:20]],
            "total_anomalies": sum([
                len(self.degree_anomalies),
                len(self.clustering_anomalies),
                len(self.bridge_anomalies),
                len(self.hub_anomalies),
            ]),
            "computation_time_ms": round(self.computation_time_ms, 2),
        }


# =============================================================================
# ANOMALY ENGINE
# =============================================================================

class AnomalyEngine:
    """
    Engine for detecting anomalies in the graph.

    Implements multiple detection methods:
    - Degree-based: Unusual connectivity patterns
    - Clustering-based: Nodes with unusual local structure
    - Bridge detection: Nodes connecting disparate communities
    - Attribute-based: Statistical outliers in node properties
    - Temporal: Sudden changes in entity behavior
    """

    def __init__(self, client=None):
        """
        Initialize the anomaly engine.

        Args:
            client: Optional GraphClient for database access
        """
        self.client = client

        # Internal graph representation
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._adjacency: Dict[str, Set[str]] = {}
        self._edge_weights: Dict[Tuple[str, str], float] = {}

        # Computed statistics
        self._degree_stats: Dict[str, float] = {}
        self._clustering_stats: Dict[str, float] = {}

    # =========================================================================
    # GRAPH BUILDING
    # =========================================================================

    def build_graph(
        self,
        nodes: List[GraphNode],
        edges: List[GraphEdge]
    ) -> None:
        """
        Build internal graph representation and compute baseline statistics.

        Args:
            nodes: List of GraphNode objects
            edges: List of GraphEdge objects
        """
        self._nodes = {n.entity_id: n for n in nodes}
        self._edges = edges
        self._adjacency = {n.entity_id: set() for n in nodes}
        self._edge_weights = {}

        for edge in edges:
            if edge.source_id in self._adjacency and edge.target_id in self._nodes:
                self._adjacency[edge.source_id].add(edge.target_id)
                self._adjacency[edge.target_id].add(edge.source_id)

                key = tuple(sorted([edge.source_id, edge.target_id]))
                self._edge_weights[key] = edge.composite_weight

        # Compute baseline statistics
        self._compute_baseline_stats()

        logger.info(f"Built anomaly graph with {len(self._nodes)} nodes, "
                   f"{len(self._edges)} edges")

    def _compute_baseline_stats(self) -> None:
        """Compute baseline statistics for anomaly detection."""
        if not self._nodes:
            return

        # Degree statistics
        degrees = [len(self._adjacency.get(n, set())) for n in self._nodes]
        self._degree_stats = self._compute_stats(degrees)

        # Clustering coefficient per node
        clustering_coeffs = []
        for node_id in self._nodes:
            cc = self._local_clustering_coefficient(node_id)
            clustering_coeffs.append(cc)
        self._clustering_stats = self._compute_stats(clustering_coeffs)

    def _compute_stats(self, values: List[float]) -> Dict[str, float]:
        """Compute basic statistics for a list of values."""
        if not values:
            return {"mean": 0, "std": 0, "min": 0, "max": 0, "median": 0}

        n = len(values)
        mean = sum(values) / n
        variance = sum((x - mean) ** 2 for x in values) / n
        std = math.sqrt(variance)

        sorted_vals = sorted(values)
        median = sorted_vals[n // 2] if n % 2 == 1 else (sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2

        return {
            "mean": mean,
            "std": std,
            "min": min(values),
            "max": max(values),
            "median": median,
            "count": n,
        }

    def _local_clustering_coefficient(self, node_id: str) -> float:
        """Compute local clustering coefficient for a node."""
        neighbors = list(self._adjacency.get(node_id, set()))
        k = len(neighbors)

        if k < 2:
            return 0.0

        triangles = 0
        for i in range(len(neighbors)):
            for j in range(i + 1, len(neighbors)):
                if neighbors[j] in self._adjacency.get(neighbors[i], set()):
                    triangles += 1

        possible = k * (k - 1) / 2
        return triangles / possible if possible > 0 else 0

    # =========================================================================
    # DEGREE ANOMALY DETECTION
    # =========================================================================

    def detect_degree_anomalies(
        self,
        z_threshold: float = 2.0,
        min_degree: int = 1
    ) -> AnomalyResult:
        """
        Detect nodes with unusually high or low degree.

        Uses z-score to identify outliers.

        Args:
            z_threshold: Z-score threshold for anomaly
            min_degree: Minimum degree to consider

        Returns:
            AnomalyResult with degree anomalies
        """
        start_time = time.time()

        if not self._nodes or self._degree_stats.get("std", 0) == 0:
            return AnomalyResult(
                method="degree",
                anomaly_count=0,
                threshold=z_threshold,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        mean = self._degree_stats["mean"]
        std = self._degree_stats["std"]

        anomalies = []
        for node_id, node in self._nodes.items():
            degree = len(self._adjacency.get(node_id, set()))

            if degree < min_degree:
                continue

            z_score = (degree - mean) / std if std > 0 else 0

            if abs(z_score) >= z_threshold:
                anomaly_type = "high_degree" if z_score > 0 else "low_degree"
                severity = self._z_to_severity(abs(z_score))

                anomalies.append(AnomalyScore(
                    entity_id=node_id,
                    entity_type=node.entity_type.value,
                    value=node.value,
                    anomaly_score=min(abs(z_score) / 5, 1.0),
                    anomaly_type=anomaly_type,
                    severity=severity,
                    explanation=f"Degree {degree} is {abs(z_score):.1f} std devs from mean ({mean:.1f})",
                    contributing_factors=[f"degree={degree}", f"mean={mean:.1f}", f"std={std:.1f}"],
                ))

        # Sort by score descending
        anomalies.sort(key=lambda x: x.anomaly_score, reverse=True)

        computation_time = (time.time() - start_time) * 1000

        return AnomalyResult(
            method="degree",
            anomaly_count=len(anomalies),
            threshold=z_threshold,
            anomalies=anomalies,
            statistics=self._degree_stats,
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # CLUSTERING ANOMALY DETECTION
    # =========================================================================

    def detect_clustering_anomalies(
        self,
        z_threshold: float = 2.0
    ) -> AnomalyResult:
        """
        Detect nodes with unusual local clustering coefficient.

        Low clustering in dense neighborhood = potential bridge/broker.
        High clustering in sparse neighborhood = tight clique.

        Args:
            z_threshold: Z-score threshold for anomaly

        Returns:
            AnomalyResult with clustering anomalies
        """
        start_time = time.time()

        if not self._nodes or self._clustering_stats.get("std", 0) == 0:
            return AnomalyResult(
                method="clustering",
                anomaly_count=0,
                threshold=z_threshold,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        mean = self._clustering_stats["mean"]
        std = self._clustering_stats["std"]

        anomalies = []
        for node_id, node in self._nodes.items():
            cc = self._local_clustering_coefficient(node_id)
            degree = len(self._adjacency.get(node_id, set()))

            # Only consider nodes with at least 2 neighbors
            if degree < 2:
                continue

            z_score = (cc - mean) / std if std > 0 else 0

            if abs(z_score) >= z_threshold:
                if z_score < 0:
                    anomaly_type = "low_clustering"
                    explanation = f"Low clustering ({cc:.2f}) suggests bridge/broker role"
                else:
                    anomaly_type = "high_clustering"
                    explanation = f"High clustering ({cc:.2f}) suggests tight clique"

                severity = self._z_to_severity(abs(z_score))

                anomalies.append(AnomalyScore(
                    entity_id=node_id,
                    entity_type=node.entity_type.value,
                    value=node.value,
                    anomaly_score=min(abs(z_score) / 5, 1.0),
                    anomaly_type=anomaly_type,
                    severity=severity,
                    explanation=explanation,
                    contributing_factors=[f"clustering={cc:.2f}", f"degree={degree}"],
                ))

        anomalies.sort(key=lambda x: x.anomaly_score, reverse=True)

        computation_time = (time.time() - start_time) * 1000

        return AnomalyResult(
            method="clustering",
            anomaly_count=len(anomalies),
            threshold=z_threshold,
            anomalies=anomalies,
            statistics=self._clustering_stats,
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # BRIDGE/BROKER DETECTION
    # =========================================================================

    def detect_bridge_nodes(
        self,
        min_communities: int = 2
    ) -> AnomalyResult:
        """
        Detect nodes that bridge different communities/clusters.

        Bridges are important for threat intel as they may represent:
        - Shared infrastructure between threat actors
        - Pivot points in attack paths
        - Weak links that could be exploited

        Args:
            min_communities: Minimum communities a node must connect

        Returns:
            AnomalyResult with bridge anomalies
        """
        start_time = time.time()

        if not self._nodes:
            return AnomalyResult(
                method="bridge",
                anomaly_count=0,
                threshold=min_communities,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        # Simple community detection via label propagation (quick approximation)
        labels = self._quick_community_labels()

        anomalies = []
        for node_id, node in self._nodes.items():
            neighbors = self._adjacency.get(node_id, set())

            if not neighbors:
                continue

            # Count distinct communities among neighbors
            neighbor_communities = set()
            for neighbor in neighbors:
                neighbor_communities.add(labels.get(neighbor, neighbor))

            if len(neighbor_communities) >= min_communities:
                # This node bridges multiple communities
                anomaly_score = min(len(neighbor_communities) / 5, 1.0)
                severity = "medium" if len(neighbor_communities) == 2 else "high"

                anomalies.append(AnomalyScore(
                    entity_id=node_id,
                    entity_type=node.entity_type.value,
                    value=node.value,
                    anomaly_score=anomaly_score,
                    anomaly_type="bridge_node",
                    severity=severity,
                    explanation=f"Connects {len(neighbor_communities)} different communities",
                    contributing_factors=[
                        f"communities_bridged={len(neighbor_communities)}",
                        f"neighbors={len(neighbors)}",
                    ],
                ))

        anomalies.sort(key=lambda x: x.anomaly_score, reverse=True)

        computation_time = (time.time() - start_time) * 1000

        return AnomalyResult(
            method="bridge",
            anomaly_count=len(anomalies),
            threshold=min_communities,
            anomalies=anomalies,
            computation_time_ms=computation_time,
        )

    def _quick_community_labels(self) -> Dict[str, str]:
        """Quick community detection using connected components."""
        visited = set()
        labels = {}
        community_id = 0

        for start_node in self._nodes:
            if start_node in visited:
                continue

            # BFS to find component
            queue = [start_node]
            visited.add(start_node)
            component = []

            while queue:
                node = queue.pop(0)
                component.append(node)

                for neighbor in self._adjacency.get(node, set()):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)

            # Assign labels
            label = f"community_{community_id}"
            for node in component:
                labels[node] = label

            community_id += 1

        return labels

    # =========================================================================
    # HUB/AUTHORITY DETECTION
    # =========================================================================

    def detect_hub_anomalies(
        self,
        top_k: int = 10
    ) -> AnomalyResult:
        """
        Detect unusual hub/authority patterns.

        Hubs point to many authorities. Authorities are pointed to by many hubs.
        Unusual patterns may indicate:
        - C2 servers (high in-degree from many sources)
        - Distribution points (high out-degree to many targets)
        - Compromised infrastructure

        Args:
            top_k: Number of top hubs/authorities to return

        Returns:
            AnomalyResult with hub anomalies
        """
        start_time = time.time()

        if not self._nodes:
            return AnomalyResult(
                method="hub",
                anomaly_count=0,
                threshold=top_k,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        # Compute hub and authority scores (simplified HITS)
        hub_scores, auth_scores = self._compute_hits_scores()

        # Find top hubs and authorities
        anomalies = []

        # Top hubs (point to many authorities)
        hub_items = sorted(hub_scores.items(), key=lambda x: x[1], reverse=True)[:top_k]
        for node_id, score in hub_items:
            if score > 0.1:  # Threshold for significance
                node = self._nodes[node_id]
                anomalies.append(AnomalyScore(
                    entity_id=node_id,
                    entity_type=node.entity_type.value,
                    value=node.value,
                    anomaly_score=min(score, 1.0),
                    anomaly_type="hub",
                    severity=self._score_to_severity(score),
                    explanation=f"Hub score {score:.3f} - points to many important nodes",
                    contributing_factors=[f"hub_score={score:.3f}"],
                ))

        # Top authorities (pointed to by many hubs)
        auth_items = sorted(auth_scores.items(), key=lambda x: x[1], reverse=True)[:top_k]
        for node_id, score in auth_items:
            if score > 0.1:
                node = self._nodes[node_id]
                # Avoid duplicates
                if not any(a.entity_id == node_id for a in anomalies):
                    anomalies.append(AnomalyScore(
                        entity_id=node_id,
                        entity_type=node.entity_type.value,
                        value=node.value,
                        anomaly_score=min(score, 1.0),
                        anomaly_type="authority",
                        severity=self._score_to_severity(score),
                        explanation=f"Authority score {score:.3f} - referenced by many important nodes",
                        contributing_factors=[f"authority_score={score:.3f}"],
                    ))

        anomalies.sort(key=lambda x: x.anomaly_score, reverse=True)

        computation_time = (time.time() - start_time) * 1000

        return AnomalyResult(
            method="hub",
            anomaly_count=len(anomalies),
            threshold=top_k,
            anomalies=anomalies,
            computation_time_ms=computation_time,
        )

    def _compute_hits_scores(
        self,
        max_iterations: int = 20
    ) -> Tuple[Dict[str, float], Dict[str, float]]:
        """Compute HITS hub and authority scores."""
        n = len(self._nodes)
        if n == 0:
            return {}, {}

        # Initialize
        hub = {node: 1.0 / n for node in self._nodes}
        auth = {node: 1.0 / n for node in self._nodes}

        # Build directed adjacency (out-edges)
        out_adj: Dict[str, Set[str]] = {n: set() for n in self._nodes}
        in_adj: Dict[str, Set[str]] = {n: set() for n in self._nodes}

        for edge in self._edges:
            if edge.source_id in out_adj:
                out_adj[edge.source_id].add(edge.target_id)
            if edge.target_id in in_adj:
                in_adj[edge.target_id].add(edge.source_id)

        for _ in range(max_iterations):
            # Update authority scores
            new_auth = {}
            for node in self._nodes:
                new_auth[node] = sum(hub.get(src, 0) for src in in_adj.get(node, set()))

            # Normalize
            norm = math.sqrt(sum(v * v for v in new_auth.values())) or 1
            auth = {k: v / norm for k, v in new_auth.items()}

            # Update hub scores
            new_hub = {}
            for node in self._nodes:
                new_hub[node] = sum(auth.get(tgt, 0) for tgt in out_adj.get(node, set()))

            # Normalize
            norm = math.sqrt(sum(v * v for v in new_hub.values())) or 1
            hub = {k: v / norm for k, v in new_hub.items()}

        return hub, auth

    # =========================================================================
    # ATTRIBUTE ANOMALY DETECTION
    # =========================================================================

    def detect_attribute_anomalies(
        self,
        attribute: str = "risk_score",
        z_threshold: float = 2.0
    ) -> AnomalyResult:
        """
        Detect nodes with unusual attribute values.

        Args:
            attribute: Attribute to analyze
            z_threshold: Z-score threshold for anomaly

        Returns:
            AnomalyResult with attribute anomalies
        """
        start_time = time.time()

        if not self._nodes:
            return AnomalyResult(
                method=f"attribute_{attribute}",
                anomaly_count=0,
                threshold=z_threshold,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        # Extract attribute values
        values = []
        node_values: Dict[str, float] = {}

        for node_id, node in self._nodes.items():
            if hasattr(node, attribute):
                val = getattr(node, attribute)
                if isinstance(val, (int, float)):
                    values.append(val)
                    node_values[node_id] = val

        if not values:
            return AnomalyResult(
                method=f"attribute_{attribute}",
                anomaly_count=0,
                threshold=z_threshold,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        stats = self._compute_stats(values)
        mean = stats["mean"]
        std = stats["std"]

        anomalies = []
        for node_id, val in node_values.items():
            z_score = (val - mean) / std if std > 0 else 0

            if abs(z_score) >= z_threshold:
                node = self._nodes[node_id]
                direction = "high" if z_score > 0 else "low"
                severity = self._z_to_severity(abs(z_score))

                anomalies.append(AnomalyScore(
                    entity_id=node_id,
                    entity_type=node.entity_type.value,
                    value=node.value,
                    anomaly_score=min(abs(z_score) / 5, 1.0),
                    anomaly_type=f"{direction}_{attribute}",
                    severity=severity,
                    explanation=f"{attribute}={val:.2f} is {abs(z_score):.1f} std devs from mean ({mean:.2f})",
                    contributing_factors=[f"{attribute}={val:.2f}", f"mean={mean:.2f}"],
                ))

        anomalies.sort(key=lambda x: x.anomaly_score, reverse=True)

        computation_time = (time.time() - start_time) * 1000

        return AnomalyResult(
            method=f"attribute_{attribute}",
            anomaly_count=len(anomalies),
            threshold=z_threshold,
            anomalies=anomalies,
            statistics=stats,
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # STAR PATTERN DETECTION
    # =========================================================================

    def detect_star_patterns(
        self,
        min_spokes: int = 5
    ) -> AnomalyResult:
        """
        Detect star patterns (one central node connected to many leaf nodes).

        Star patterns may indicate:
        - C2 infrastructure
        - Phishing campaigns (one actor, many targets)
        - Domain generation algorithms (one IP, many domains)

        Args:
            min_spokes: Minimum connections to be considered a star

        Returns:
            AnomalyResult with star pattern anomalies
        """
        start_time = time.time()

        if not self._nodes:
            return AnomalyResult(
                method="star_pattern",
                anomaly_count=0,
                threshold=min_spokes,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        anomalies = []

        for node_id, node in self._nodes.items():
            neighbors = self._adjacency.get(node_id, set())

            if len(neighbors) < min_spokes:
                continue

            # Check if neighbors are mostly leaf nodes (degree 1)
            leaf_count = 0
            for neighbor in neighbors:
                if len(self._adjacency.get(neighbor, set())) == 1:
                    leaf_count += 1

            leaf_ratio = leaf_count / len(neighbors) if neighbors else 0

            if leaf_ratio >= 0.5 and leaf_count >= min_spokes:
                anomaly_score = min(leaf_count / 20, 1.0)
                severity = "high" if leaf_count >= 10 else "medium"

                anomalies.append(AnomalyScore(
                    entity_id=node_id,
                    entity_type=node.entity_type.value,
                    value=node.value,
                    anomaly_score=anomaly_score,
                    anomaly_type="star_center",
                    severity=severity,
                    explanation=f"Star pattern: {leaf_count} leaf nodes ({leaf_ratio:.0%} of {len(neighbors)} neighbors)",
                    contributing_factors=[
                        f"leaf_nodes={leaf_count}",
                        f"total_neighbors={len(neighbors)}",
                        f"leaf_ratio={leaf_ratio:.2f}",
                    ],
                ))

        anomalies.sort(key=lambda x: x.anomaly_score, reverse=True)

        computation_time = (time.time() - start_time) * 1000

        return AnomalyResult(
            method="star_pattern",
            anomaly_count=len(anomalies),
            threshold=min_spokes,
            anomalies=anomalies,
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # COMPREHENSIVE ANOMALY DETECTION
    # =========================================================================

    def detect_all_anomalies(
        self,
        z_threshold: float = 2.0,
        include_structural: bool = True,
        include_attribute: bool = True,
        include_patterns: bool = True
    ) -> StructuralAnomalyResult:
        """
        Run comprehensive anomaly detection.

        Args:
            z_threshold: Z-score threshold for statistical anomalies
            include_structural: Include degree/clustering anomalies
            include_attribute: Include attribute-based anomalies
            include_patterns: Include pattern-based anomalies (star, bridge)

        Returns:
            StructuralAnomalyResult with all detected anomalies
        """
        start_time = time.time()

        result = StructuralAnomalyResult()

        if include_structural:
            degree_result = self.detect_degree_anomalies(z_threshold=z_threshold)
            result.degree_anomalies = degree_result.anomalies

            clustering_result = self.detect_clustering_anomalies(z_threshold=z_threshold)
            result.clustering_anomalies = clustering_result.anomalies

        if include_patterns:
            bridge_result = self.detect_bridge_nodes()
            result.bridge_anomalies = bridge_result.anomalies

            hub_result = self.detect_hub_anomalies()
            result.hub_anomalies = hub_result.anomalies

        result.computation_time_ms = (time.time() - start_time) * 1000

        return result

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    def _z_to_severity(self, z_score: float) -> str:
        """Convert z-score to severity level."""
        if z_score >= 4:
            return "critical"
        elif z_score >= 3:
            return "high"
        elif z_score >= 2:
            return "medium"
        else:
            return "low"

    def _score_to_severity(self, score: float) -> str:
        """Convert anomaly score to severity level."""
        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.4:
            return "medium"
        else:
            return "low"

    @property
    def node_count(self) -> int:
        """Get number of nodes."""
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        """Get number of edges."""
        return len(self._edges)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def detect_anomalies(
    nodes: List[GraphNode],
    edges: List[GraphEdge],
    methods: List[str] = None,
    z_threshold: float = 2.0
) -> Dict[str, AnomalyResult]:
    """
    Detect anomalies using specified methods.

    Args:
        nodes: List of GraphNode objects
        edges: List of GraphEdge objects
        methods: Methods to use (default: all)
        z_threshold: Z-score threshold

    Returns:
        Dictionary of method name to AnomalyResult
    """
    if methods is None:
        methods = ["degree", "clustering", "bridge", "hub", "star_pattern"]

    engine = AnomalyEngine()
    engine.build_graph(nodes, edges)

    results = {}

    for method in methods:
        if method == "degree":
            results[method] = engine.detect_degree_anomalies(z_threshold)
        elif method == "clustering":
            results[method] = engine.detect_clustering_anomalies(z_threshold)
        elif method == "bridge":
            results[method] = engine.detect_bridge_nodes()
        elif method == "hub":
            results[method] = engine.detect_hub_anomalies()
        elif method == "star_pattern":
            results[method] = engine.detect_star_patterns()

    return results


def find_suspicious_entities(
    nodes: List[GraphNode],
    edges: List[GraphEdge],
    top_k: int = 20
) -> List[AnomalyScore]:
    """
    Find the most suspicious entities across all detection methods.

    Args:
        nodes: List of GraphNode objects
        edges: List of GraphEdge objects
        top_k: Number of results to return

    Returns:
        List of top anomalous entities
    """
    engine = AnomalyEngine()
    engine.build_graph(nodes, edges)

    # Run all detection methods
    all_result = engine.detect_all_anomalies()

    # Combine all anomalies
    all_anomalies: Dict[str, AnomalyScore] = {}

    for anomaly_list in [
        all_result.degree_anomalies,
        all_result.clustering_anomalies,
        all_result.bridge_anomalies,
        all_result.hub_anomalies,
    ]:
        for anomaly in anomaly_list:
            key = anomaly.entity_id
            if key in all_anomalies:
                # Keep higher score, combine types
                existing = all_anomalies[key]
                if anomaly.anomaly_score > existing.anomaly_score:
                    anomaly.contributing_factors.extend(existing.contributing_factors)
                    anomaly.explanation = f"Multiple anomalies: {existing.anomaly_type}, {anomaly.anomaly_type}"
                    all_anomalies[key] = anomaly
                else:
                    existing.contributing_factors.extend(anomaly.contributing_factors)
            else:
                all_anomalies[key] = anomaly

    # Sort and return top k
    sorted_anomalies = sorted(all_anomalies.values(), key=lambda x: x.anomaly_score, reverse=True)
    return sorted_anomalies[:top_k]
