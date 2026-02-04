#!/usr/bin/env python3
"""
Graph Centrality Algorithms

Computes various centrality measures to identify important nodes in the graph.
Uses NetworkX for algorithm implementation with Neo4j/mock backend for storage.

Centrality Measures:
- Degree Centrality: How connected is a node?
- Betweenness Centrality: How often does a node lie on shortest paths?
- Closeness Centrality: How close is a node to all others?
- Eigenvector Centrality: How connected to important nodes?
- PageRank: Influence based on who links to you
- Harmonic Centrality: Closeness variant for disconnected graphs
- Katz Centrality: Influence accounting for path length
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    nx = None

from ..models import (
    CentralityScores,
    ExtendedEntityType,
    ExtendedRelationshipType,
    GraphNode,
    GraphEdge,
    GraphStatistics,
)

logger = logging.getLogger(__name__)


# =============================================================================
# RESULT CLASSES
# =============================================================================

@dataclass
class CentralityResult:
    """Result of centrality computation."""
    algorithm: str
    node_count: int
    computed_at: datetime = field(default_factory=datetime.utcnow)
    computation_time_ms: float = 0.0
    scores: Dict[str, float] = field(default_factory=dict)
    top_nodes: List[Tuple[str, float]] = field(default_factory=list)
    statistics: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "node_count": self.node_count,
            "computed_at": self.computed_at.isoformat(),
            "computation_time_ms": round(self.computation_time_ms, 2),
            "top_nodes": [
                {"entity_id": eid, "score": round(score, 6)}
                for eid, score in self.top_nodes[:20]
            ],
            "statistics": {k: round(v, 6) for k, v in self.statistics.items()},
        }


@dataclass
class AllCentralityResult:
    """Result of computing all centrality measures."""
    node_count: int
    edge_count: int
    computed_at: datetime = field(default_factory=datetime.utcnow)
    total_computation_time_ms: float = 0.0
    scores: Dict[str, CentralityScores] = field(default_factory=dict)
    algorithm_times: Dict[str, float] = field(default_factory=dict)
    top_by_composite: List[Tuple[str, float]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "computed_at": self.computed_at.isoformat(),
            "total_computation_time_ms": round(self.total_computation_time_ms, 2),
            "algorithm_times": {k: round(v, 2) for k, v in self.algorithm_times.items()},
            "top_by_composite": [
                {"entity_id": eid, "score": round(score, 6)}
                for eid, score in self.top_by_composite[:20]
            ],
            "sample_scores": {
                eid: scores.to_dict()
                for eid, scores in list(self.scores.items())[:10]
            },
        }


# =============================================================================
# CENTRALITY ENGINE
# =============================================================================

class CentralityEngine:
    """
    Computes centrality measures for graph nodes.

    Uses NetworkX for algorithm computation. Can work with:
    - GraphClient for database-backed graphs
    - Direct node/edge lists for in-memory computation
    """

    def __init__(self, client=None):
        """
        Initialize the centrality engine.

        Args:
            client: Optional GraphClient for database access
        """
        self.client = client
        self._graph: Optional[nx.DiGraph] = None
        self._entity_id_map: Dict[str, int] = {}  # entity_id -> nx node id
        self._reverse_map: Dict[int, str] = {}    # nx node id -> entity_id

        if not NETWORKX_AVAILABLE:
            logger.warning("NetworkX not installed. Centrality algorithms will use fallback.")

    # =========================================================================
    # GRAPH BUILDING
    # =========================================================================

    def build_graph_from_client(
        self,
        entity_types: List[ExtendedEntityType] = None,
        relationship_types: List[ExtendedRelationshipType] = None,
        investigation_id: str = None,
    ) -> nx.DiGraph:
        """
        Build NetworkX graph from GraphClient data.

        Args:
            entity_types: Filter by entity types (None = all)
            relationship_types: Filter by relationship types (None = all)
            investigation_id: Filter by investigation (None = all)

        Returns:
            NetworkX DiGraph
        """
        if not self.client:
            raise ValueError("No GraphClient configured")

        nodes = []
        edges = []

        # Get nodes
        if investigation_id:
            nodes = self.client.get_nodes_by_investigation(investigation_id)
        elif entity_types:
            for et in entity_types:
                nodes.extend(self.client.get_nodes_by_type(et, limit=10000))
        else:
            # Get all nodes via statistics then fetch by type
            stats = self.client.get_statistics()
            for entity_type in stats.nodes_by_type.keys():
                et = ExtendedEntityType.from_string(entity_type)
                nodes.extend(self.client.get_nodes_by_type(et, limit=10000))

        # Get edges for all nodes
        node_ids = {n.entity_id for n in nodes}
        for node in nodes:
            node_edges = self.client.get_edges_for_node(node.entity_id, direction="out")
            for edge in node_edges:
                if relationship_types and edge.relationship_type not in relationship_types:
                    continue
                if edge.target_id in node_ids:
                    edges.append(edge)

        return self.build_graph(nodes, edges)

    def build_graph(
        self,
        nodes: List[GraphNode],
        edges: List[GraphEdge]
    ) -> Any:
        """
        Build graph from node and edge lists.

        Args:
            nodes: List of GraphNode objects
            edges: List of GraphEdge objects

        Returns:
            NetworkX DiGraph if available, otherwise internal representation
        """
        self._entity_id_map = {}
        self._reverse_map = {}

        # Build entity mappings regardless of NetworkX availability
        for i, node in enumerate(nodes):
            self._entity_id_map[node.entity_id] = i
            self._reverse_map[i] = node.entity_id

        # Store edges for fallback algorithms
        self._edges = edges
        self._nodes = nodes

        if not NETWORKX_AVAILABLE:
            logger.warning("NetworkX not available, using fallback algorithms")
            # Create a simple adjacency representation
            self._adjacency: Dict[str, List[str]] = {n.entity_id: [] for n in nodes}
            self._in_adjacency: Dict[str, List[str]] = {n.entity_id: [] for n in nodes}
            for edge in edges:
                if edge.source_id in self._adjacency and edge.target_id in self._adjacency:
                    self._adjacency[edge.source_id].append(edge.target_id)
                    self._in_adjacency[edge.target_id].append(edge.source_id)
                    if edge.bidirectional:
                        self._adjacency[edge.target_id].append(edge.source_id)
                        self._in_adjacency[edge.source_id].append(edge.target_id)
            self._graph = True  # Mark as built
            return self._adjacency

        self._graph = nx.DiGraph()

        # Add nodes
        for i, node in enumerate(nodes):
            self._entity_id_map[node.entity_id] = i
            self._reverse_map[i] = node.entity_id
            self._graph.add_node(
                i,
                entity_id=node.entity_id,
                entity_type=node.entity_type.value,
                value=node.value,
                confidence=node.confidence,
                risk_score=node.risk_score,
            )

        # Add edges
        for edge in edges:
            source_idx = self._entity_id_map.get(edge.source_id)
            target_idx = self._entity_id_map.get(edge.target_id)

            if source_idx is not None and target_idx is not None:
                self._graph.add_edge(
                    source_idx,
                    target_idx,
                    relationship_type=edge.relationship_type.value,
                    weight=edge.composite_weight,
                    confidence=edge.confidence,
                )

                # Add reverse edge for bidirectional relationships
                if edge.bidirectional:
                    self._graph.add_edge(
                        target_idx,
                        source_idx,
                        relationship_type=edge.relationship_type.value,
                        weight=edge.composite_weight,
                        confidence=edge.confidence,
                    )

        logger.info(f"Built graph with {self._graph.number_of_nodes()} nodes, "
                   f"{self._graph.number_of_edges()} edges")

        return self._graph

    # =========================================================================
    # INDIVIDUAL CENTRALITY ALGORITHMS
    # =========================================================================

    def degree_centrality(
        self,
        normalized: bool = True
    ) -> CentralityResult:
        """
        Compute degree centrality for all nodes.

        Degree centrality is the fraction of nodes connected to a node.
        High degree = many connections = potentially important hub.

        Args:
            normalized: Normalize by max possible degree

        Returns:
            CentralityResult with scores
        """
        if not self._graph:
            raise ValueError("No graph built. Call build_graph first.")

        start_time = time.time()
        algorithm = "degree_centrality"

        if NETWORKX_AVAILABLE and hasattr(self._graph, 'in_degree'):
            # Compute in/out degree separately for directed graph
            in_degree = dict(self._graph.in_degree())
            out_degree = dict(self._graph.out_degree())

            n = self._graph.number_of_nodes()
            max_degree = n - 1 if n > 1 else 1

            scores = {}
            for node_idx in self._graph.nodes():
                entity_id = self._reverse_map[node_idx]
                total = in_degree[node_idx] + out_degree[node_idx]
                if normalized:
                    scores[entity_id] = total / (2 * max_degree) if max_degree > 0 else 0
                else:
                    scores[entity_id] = float(total)
        else:
            scores = self._fallback_degree_centrality(normalized)

        computation_time = (time.time() - start_time) * 1000

        # Get top nodes
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)

        # Compute statistics
        values = list(scores.values())
        statistics = self._compute_statistics(values)

        return CentralityResult(
            algorithm=algorithm,
            node_count=len(scores),
            computation_time_ms=computation_time,
            scores=scores,
            top_nodes=sorted_scores[:50],
            statistics=statistics,
        )

    def in_degree_centrality(self) -> CentralityResult:
        """
        Compute in-degree centrality (incoming connections only).

        High in-degree = many things point to this node = authoritative.
        """
        if not self._graph:
            raise ValueError("No graph built. Call build_graph first.")

        start_time = time.time()

        if NETWORKX_AVAILABLE and hasattr(self._graph, 'in_degree'):
            raw_scores = nx.in_degree_centrality(self._graph)
            scores = {self._reverse_map[k]: v for k, v in raw_scores.items()}
        else:
            scores = self._fallback_in_degree_centrality()

        computation_time = (time.time() - start_time) * 1000
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)

        return CentralityResult(
            algorithm="in_degree_centrality",
            node_count=len(scores),
            computation_time_ms=computation_time,
            scores=scores,
            top_nodes=sorted_scores[:50],
            statistics=self._compute_statistics(list(scores.values())),
        )

    def out_degree_centrality(self) -> CentralityResult:
        """
        Compute out-degree centrality (outgoing connections only).

        High out-degree = this node connects to many others = hub.
        """
        if not self._graph:
            raise ValueError("No graph built. Call build_graph first.")

        start_time = time.time()

        if NETWORKX_AVAILABLE and hasattr(self._graph, 'out_degree'):
            raw_scores = nx.out_degree_centrality(self._graph)
            scores = {self._reverse_map[k]: v for k, v in raw_scores.items()}
        else:
            scores = self._fallback_out_degree_centrality()

        computation_time = (time.time() - start_time) * 1000
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)

        return CentralityResult(
            algorithm="out_degree_centrality",
            node_count=len(scores),
            computation_time_ms=computation_time,
            scores=scores,
            top_nodes=sorted_scores[:50],
            statistics=self._compute_statistics(list(scores.values())),
        )

    def betweenness_centrality(
        self,
        k: int = None,
        normalized: bool = True,
        weight: str = "weight",
        endpoints: bool = False
    ) -> CentralityResult:
        """
        Compute betweenness centrality for all nodes.

        Betweenness measures how often a node lies on shortest paths between
        other nodes. High betweenness = bridge/broker in the network.

        Args:
            k: Sample size for approximation (None = exact)
            normalized: Normalize by number of node pairs
            weight: Edge attribute for weights (None = unweighted)
            endpoints: Include endpoints in path counts

        Returns:
            CentralityResult with scores
        """
        if not self._graph:
            raise ValueError("No graph built. Call build_graph first.")

        start_time = time.time()

        if NETWORKX_AVAILABLE and hasattr(self._graph, 'nodes'):
            raw_scores = nx.betweenness_centrality(
                self._graph,
                k=k,
                normalized=normalized,
                weight=weight,
                endpoints=endpoints,
            )
            scores = {self._reverse_map[k]: v for k, v in raw_scores.items()}
        else:
            scores = self._fallback_betweenness_centrality()

        computation_time = (time.time() - start_time) * 1000
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)

        return CentralityResult(
            algorithm="betweenness_centrality",
            node_count=len(scores),
            computation_time_ms=computation_time,
            scores=scores,
            top_nodes=sorted_scores[:50],
            statistics=self._compute_statistics(list(scores.values())),
        )

    def closeness_centrality(
        self,
        wf_improved: bool = True
    ) -> CentralityResult:
        """
        Compute closeness centrality for all nodes.

        Closeness measures how close a node is to all other nodes.
        High closeness = can quickly reach/influence the entire network.

        Args:
            wf_improved: Use Wasserman-Faust improved formula for disconnected graphs

        Returns:
            CentralityResult with scores
        """
        if not self._graph:
            raise ValueError("No graph built. Call build_graph first.")

        start_time = time.time()

        if NETWORKX_AVAILABLE and hasattr(self._graph, 'nodes'):
            raw_scores = nx.closeness_centrality(
                self._graph,
                wf_improved=wf_improved,
            )
            scores = {self._reverse_map[k]: v for k, v in raw_scores.items()}
        else:
            scores = self._fallback_closeness_centrality()

        computation_time = (time.time() - start_time) * 1000
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)

        return CentralityResult(
            algorithm="closeness_centrality",
            node_count=len(scores),
            computation_time_ms=computation_time,
            scores=scores,
            top_nodes=sorted_scores[:50],
            statistics=self._compute_statistics(list(scores.values())),
        )

    def eigenvector_centrality(
        self,
        max_iter: int = 1000,
        tol: float = 1e-6
    ) -> CentralityResult:
        """
        Compute eigenvector centrality for all nodes.

        Eigenvector centrality measures influence based on connections to
        other influential nodes. High eigenvector = connected to important nodes.

        Args:
            max_iter: Maximum iterations for power iteration
            tol: Convergence tolerance

        Returns:
            CentralityResult with scores
        """
        if not self._graph:
            raise ValueError("No graph built. Call build_graph first.")

        start_time = time.time()

        if NETWORKX_AVAILABLE and hasattr(self._graph, 'to_undirected'):
            try:
                # Use undirected version for eigenvector centrality
                undirected = self._graph.to_undirected()
                raw_scores = nx.eigenvector_centrality(
                    undirected,
                    max_iter=max_iter,
                    tol=tol,
                )
                scores = {self._reverse_map[k]: v for k, v in raw_scores.items()}
            except nx.PowerIterationFailedConvergence:
                logger.warning("Eigenvector centrality did not converge, using degree fallback")
                scores = self.degree_centrality().scores
        else:
            scores = self._fallback_eigenvector_centrality()

        computation_time = (time.time() - start_time) * 1000
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)

        return CentralityResult(
            algorithm="eigenvector_centrality",
            node_count=len(scores),
            computation_time_ms=computation_time,
            scores=scores,
            top_nodes=sorted_scores[:50],
            statistics=self._compute_statistics(list(scores.values())),
        )

    def pagerank(
        self,
        alpha: float = 0.85,
        personalization: Dict[str, float] = None,
        max_iter: int = 100,
        tol: float = 1e-6,
        weight: str = "weight"
    ) -> CentralityResult:
        """
        Compute PageRank centrality for all nodes.

        PageRank measures importance based on incoming links from important nodes.
        Originally developed by Google for web page ranking.

        Args:
            alpha: Damping factor (probability of following a link)
            personalization: Personalization vector (entity_id -> weight)
            max_iter: Maximum iterations
            tol: Convergence tolerance
            weight: Edge attribute for weights

        Returns:
            CentralityResult with scores
        """
        if not self._graph:
            raise ValueError("No graph built. Call build_graph first.")

        start_time = time.time()

        if NETWORKX_AVAILABLE and hasattr(self._graph, 'nodes'):
            # Convert personalization to node indices
            pers = None
            if personalization:
                pers = {}
                for entity_id, wt in personalization.items():
                    if entity_id in self._entity_id_map:
                        pers[self._entity_id_map[entity_id]] = wt

            raw_scores = nx.pagerank(
                self._graph,
                alpha=alpha,
                personalization=pers,
                max_iter=max_iter,
                tol=tol,
                weight=weight,
            )
            scores = {self._reverse_map[k]: v for k, v in raw_scores.items()}
        else:
            scores = self._fallback_pagerank(alpha)

        computation_time = (time.time() - start_time) * 1000
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)

        return CentralityResult(
            algorithm="pagerank",
            node_count=len(scores),
            computation_time_ms=computation_time,
            scores=scores,
            top_nodes=sorted_scores[:50],
            statistics=self._compute_statistics(list(scores.values())),
        )

    def harmonic_centrality(self) -> CentralityResult:
        """
        Compute harmonic centrality for all nodes.

        Harmonic centrality is a variant of closeness that handles disconnected
        graphs better by using the sum of inverse distances.

        Returns:
            CentralityResult with scores
        """
        if not self._graph:
            raise ValueError("No graph built. Call build_graph first.")

        start_time = time.time()

        if NETWORKX_AVAILABLE and hasattr(self._graph, 'nodes'):
            raw_scores = nx.harmonic_centrality(self._graph)
            scores = {self._reverse_map[k]: v for k, v in raw_scores.items()}
        else:
            # Harmonic is similar to closeness, use same fallback
            scores = self._fallback_closeness_centrality()

        computation_time = (time.time() - start_time) * 1000
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)

        return CentralityResult(
            algorithm="harmonic_centrality",
            node_count=len(scores),
            computation_time_ms=computation_time,
            scores=scores,
            top_nodes=sorted_scores[:50],
            statistics=self._compute_statistics(list(scores.values())),
        )

    def katz_centrality(
        self,
        alpha: float = 0.1,
        beta: float = 1.0,
        max_iter: int = 1000,
        tol: float = 1e-6
    ) -> CentralityResult:
        """
        Compute Katz centrality for all nodes.

        Katz centrality measures influence based on total number of walks
        between nodes, with longer walks weighted less.

        Args:
            alpha: Attenuation factor (should be < 1/largest eigenvalue)
            beta: Weight for immediate neighbors
            max_iter: Maximum iterations
            tol: Convergence tolerance

        Returns:
            CentralityResult with scores
        """
        if not self._graph:
            raise ValueError("No graph built. Call build_graph first.")

        start_time = time.time()

        if NETWORKX_AVAILABLE and hasattr(self._graph, 'nodes'):
            try:
                raw_scores = nx.katz_centrality(
                    self._graph,
                    alpha=alpha,
                    beta=beta,
                    max_iter=max_iter,
                    tol=tol,
                )
                scores = {self._reverse_map[k]: v for k, v in raw_scores.items()}
            except nx.PowerIterationFailedConvergence:
                logger.warning("Katz centrality did not converge, using PageRank fallback")
                scores = self.pagerank().scores
        else:
            # Katz is similar to PageRank, use same fallback
            scores = self._fallback_pagerank(alpha)

        computation_time = (time.time() - start_time) * 1000
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)

        return CentralityResult(
            algorithm="katz_centrality",
            node_count=len(scores),
            computation_time_ms=computation_time,
            scores=scores,
            top_nodes=sorted_scores[:50],
            statistics=self._compute_statistics(list(scores.values())),
        )

    # =========================================================================
    # COMPOSITE CENTRALITY
    # =========================================================================

    def compute_all_centrality(
        self,
        update_nodes: bool = False
    ) -> AllCentralityResult:
        """
        Compute all centrality measures for all nodes.

        Args:
            update_nodes: If True and client is set, update node records

        Returns:
            AllCentralityResult with all scores
        """
        if not self._graph:
            raise ValueError("No graph built. Call build_graph first.")

        start_time = time.time()
        algorithm_times = {}
        all_scores: Dict[str, CentralityScores] = {}

        # Initialize scores for all nodes
        for entity_id in self._entity_id_map.keys():
            all_scores[entity_id] = CentralityScores(
                node_id="",
                entity_id=entity_id,
            )

        # Compute each centrality measure
        algorithms = [
            ("degree", self.degree_centrality),
            ("in_degree", self.in_degree_centrality),
            ("out_degree", self.out_degree_centrality),
            ("betweenness", self.betweenness_centrality),
            ("closeness", self.closeness_centrality),
            ("eigenvector", self.eigenvector_centrality),
            ("pagerank", self.pagerank),
            ("harmonic", self.harmonic_centrality),
            ("katz", self.katz_centrality),
        ]

        for name, func in algorithms:
            try:
                result = func()
                algorithm_times[name] = result.computation_time_ms

                # Store scores
                for entity_id, score in result.scores.items():
                    if entity_id in all_scores:
                        setattr(all_scores[entity_id], name, score)

                logger.debug(f"Computed {name} centrality in {result.computation_time_ms:.2f}ms")
            except Exception as e:
                logger.error(f"Failed to compute {name} centrality: {e}")
                algorithm_times[name] = 0.0

        total_time = (time.time() - start_time) * 1000

        # Compute composite scores and rank
        composite_scores = [
            (entity_id, scores.composite)
            for entity_id, scores in all_scores.items()
        ]
        composite_scores.sort(key=lambda x: x[1], reverse=True)

        # Update nodes in database if requested
        if update_nodes and self.client:
            self._update_node_centrality(all_scores)

        return AllCentralityResult(
            node_count=len(all_scores),
            edge_count=self.edge_count,
            total_computation_time_ms=total_time,
            scores=all_scores,
            algorithm_times=algorithm_times,
            top_by_composite=composite_scores[:50],
        )

    def compute_centrality_for_node(self, entity_id: str) -> Optional[CentralityScores]:
        """
        Get centrality scores for a specific node.

        Args:
            entity_id: Entity ID to get scores for

        Returns:
            CentralityScores for the node, or None if not found
        """
        result = self.compute_all_centrality()
        return result.scores.get(entity_id)

    # =========================================================================
    # NODE UPDATES
    # =========================================================================

    def _update_node_centrality(
        self,
        scores: Dict[str, CentralityScores]
    ) -> int:
        """
        Update nodes in database with centrality scores.

        Args:
            scores: Entity ID -> CentralityScores mapping

        Returns:
            Number of nodes updated
        """
        if not self.client:
            return 0

        updated = 0
        for entity_id, centrality in scores.items():
            try:
                node = self.client.get_node(entity_id)
                if node:
                    node.degree_centrality = centrality.degree
                    node.betweenness_centrality = centrality.betweenness
                    node.closeness_centrality = centrality.closeness
                    node.eigenvector_centrality = centrality.eigenvector
                    node.pagerank = centrality.pagerank
                    self.client.update_node(node)
                    updated += 1
            except Exception as e:
                logger.error(f"Failed to update node {entity_id}: {e}")

        logger.info(f"Updated centrality scores for {updated} nodes")
        return updated

    # =========================================================================
    # FALLBACK IMPLEMENTATIONS (when NetworkX unavailable)
    # =========================================================================

    def _fallback_degree_centrality(self, normalized: bool = True) -> Dict[str, float]:
        """Simple degree centrality without NetworkX."""
        scores = {}
        n = len(self._entity_id_map)
        max_degree = n - 1 if n > 1 else 1

        for entity_id in self._entity_id_map.keys():
            out_degree = len(self._adjacency.get(entity_id, []))
            in_degree = len(self._in_adjacency.get(entity_id, []))
            total = out_degree + in_degree

            if normalized:
                scores[entity_id] = total / (2 * max_degree) if max_degree > 0 else 0
            else:
                scores[entity_id] = float(total)

        return scores

    def _fallback_in_degree_centrality(self) -> Dict[str, float]:
        """In-degree centrality without NetworkX."""
        scores = {}
        n = len(self._entity_id_map)
        max_degree = n - 1 if n > 1 else 1

        for entity_id in self._entity_id_map.keys():
            in_degree = len(self._in_adjacency.get(entity_id, []))
            scores[entity_id] = in_degree / max_degree if max_degree > 0 else 0

        return scores

    def _fallback_out_degree_centrality(self) -> Dict[str, float]:
        """Out-degree centrality without NetworkX."""
        scores = {}
        n = len(self._entity_id_map)
        max_degree = n - 1 if n > 1 else 1

        for entity_id in self._entity_id_map.keys():
            out_degree = len(self._adjacency.get(entity_id, []))
            scores[entity_id] = out_degree / max_degree if max_degree > 0 else 0

        return scores

    def _fallback_betweenness_centrality(self) -> Dict[str, float]:
        """
        Simple betweenness approximation without NetworkX.
        Uses BFS to find shortest paths.
        """
        scores = {eid: 0.0 for eid in self._entity_id_map.keys()}
        nodes = list(self._entity_id_map.keys())
        n = len(nodes)

        if n <= 2:
            return scores

        # For each pair of nodes, find shortest path and count intermediaries
        for source in nodes:
            # BFS from source
            distances = {source: 0}
            predecessors: Dict[str, List[str]] = {source: []}
            queue = [source]
            visited = {source}

            while queue:
                current = queue.pop(0)
                for neighbor in self._adjacency.get(current, []):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        distances[neighbor] = distances[current] + 1
                        predecessors[neighbor] = [current]
                        queue.append(neighbor)
                    elif distances.get(neighbor, float('inf')) == distances[current] + 1:
                        predecessors[neighbor].append(current)

            # Count contributions
            for target in nodes:
                if target != source and target in distances:
                    # Backtrack and count
                    path_nodes = set()
                    queue = [target]
                    while queue:
                        node = queue.pop(0)
                        for pred in predecessors.get(node, []):
                            if pred != source:
                                path_nodes.add(pred)
                                queue.append(pred)

                    for node in path_nodes:
                        scores[node] += 1.0

        # Normalize
        norm = (n - 1) * (n - 2)
        if norm > 0:
            for entity_id in scores:
                scores[entity_id] /= norm

        return scores

    def _fallback_closeness_centrality(self) -> Dict[str, float]:
        """
        Simple closeness centrality without NetworkX.
        Uses BFS for shortest path distances.
        """
        scores = {}
        nodes = list(self._entity_id_map.keys())
        n = len(nodes)

        for source in nodes:
            # BFS to compute distances
            distances = {source: 0}
            queue = [source]

            while queue:
                current = queue.pop(0)
                for neighbor in self._adjacency.get(current, []):
                    if neighbor not in distances:
                        distances[neighbor] = distances[current] + 1
                        queue.append(neighbor)

            # Closeness = (n-1) / sum of distances
            total_distance = sum(distances.values())
            reachable = len(distances) - 1  # Exclude self

            if reachable > 0 and total_distance > 0:
                scores[source] = reachable / total_distance
            else:
                scores[source] = 0.0

        return scores

    def _fallback_pagerank(self, alpha: float = 0.85) -> Dict[str, float]:
        """Simple PageRank approximation without NetworkX."""
        n = len(self._entity_id_map)
        if n == 0:
            return {}

        # Initialize with uniform distribution
        scores = {eid: 1.0 / n for eid in self._entity_id_map.keys()}

        # Compute out-degrees
        out_degrees = {eid: len(self._adjacency.get(eid, [])) for eid in self._entity_id_map.keys()}

        # Power iteration
        for _ in range(30):
            new_scores = {}
            for entity_id in self._entity_id_map.keys():
                rank = (1 - alpha) / n

                # Sum contributions from incoming edges
                for source_id in self._in_adjacency.get(entity_id, []):
                    if out_degrees[source_id] > 0:
                        rank += alpha * scores[source_id] / out_degrees[source_id]

                new_scores[entity_id] = rank

            # Handle dangling nodes (no outgoing edges)
            dangling_sum = sum(scores[eid] for eid in self._entity_id_map.keys()
                             if out_degrees[eid] == 0)
            if dangling_sum > 0:
                for entity_id in new_scores:
                    new_scores[entity_id] += alpha * dangling_sum / n

            scores = new_scores

        return scores

    def _fallback_eigenvector_centrality(self) -> Dict[str, float]:
        """Simple eigenvector centrality approximation."""
        n = len(self._entity_id_map)
        if n == 0:
            return {}

        # Initialize
        scores = {eid: 1.0 for eid in self._entity_id_map.keys()}

        # Power iteration
        for _ in range(50):
            new_scores = {}
            for entity_id in self._entity_id_map.keys():
                # Sum of neighbor scores (undirected - use both in and out)
                neighbors = set(self._adjacency.get(entity_id, []))
                neighbors.update(self._in_adjacency.get(entity_id, []))
                score = sum(scores[n] for n in neighbors) if neighbors else 0
                new_scores[entity_id] = score

            # Normalize
            norm = sum(v * v for v in new_scores.values()) ** 0.5
            if norm > 0:
                for eid in new_scores:
                    new_scores[eid] /= norm
            else:
                new_scores = {eid: 1.0 / n for eid in self._entity_id_map.keys()}

            scores = new_scores

        return scores

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    def _compute_statistics(self, values: List[float]) -> Dict[str, float]:
        """Compute statistics for a list of values."""
        if not values:
            return {"min": 0, "max": 0, "mean": 0, "std": 0, "median": 0}

        n = len(values)
        sorted_values = sorted(values)

        mean_val = sum(values) / n
        variance = sum((x - mean_val) ** 2 for x in values) / n
        std_val = variance ** 0.5

        return {
            "min": min(values),
            "max": max(values),
            "mean": mean_val,
            "std": std_val,
            "median": sorted_values[n // 2],
        }

    @property
    def graph(self) -> Any:
        """Get the underlying graph (NetworkX DiGraph or adjacency dict)."""
        return self._graph

    @property
    def node_count(self) -> int:
        """Get number of nodes in the graph."""
        if not self._graph:
            return 0
        if NETWORKX_AVAILABLE and hasattr(self._graph, 'number_of_nodes'):
            return self._graph.number_of_nodes()
        return len(self._entity_id_map)

    @property
    def edge_count(self) -> int:
        """Get number of edges in the graph."""
        if not self._graph:
            return 0
        if NETWORKX_AVAILABLE and hasattr(self._graph, 'number_of_edges'):
            return self._graph.number_of_edges()
        # For fallback mode, count total edges in adjacency list
        if hasattr(self, '_adjacency'):
            return sum(len(neighbors) for neighbors in self._adjacency.values())
        return len(getattr(self, '_edges', []))


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def compute_centrality(
    nodes: List[GraphNode],
    edges: List[GraphEdge],
    algorithms: List[str] = None
) -> AllCentralityResult:
    """
    Compute centrality measures for a graph defined by nodes and edges.

    Args:
        nodes: List of GraphNode objects
        edges: List of GraphEdge objects
        algorithms: List of algorithms to run (None = all)

    Returns:
        AllCentralityResult with scores
    """
    engine = CentralityEngine()
    engine.build_graph(nodes, edges)
    return engine.compute_all_centrality()


def get_top_central_nodes(
    nodes: List[GraphNode],
    edges: List[GraphEdge],
    algorithm: str = "pagerank",
    top_k: int = 10
) -> List[Tuple[str, float]]:
    """
    Get the top-k most central nodes by a specific algorithm.

    Args:
        nodes: List of GraphNode objects
        edges: List of GraphEdge objects
        algorithm: Centrality algorithm to use
        top_k: Number of top nodes to return

    Returns:
        List of (entity_id, score) tuples
    """
    engine = CentralityEngine()
    engine.build_graph(nodes, edges)

    algorithm_map = {
        "degree": engine.degree_centrality,
        "betweenness": engine.betweenness_centrality,
        "closeness": engine.closeness_centrality,
        "eigenvector": engine.eigenvector_centrality,
        "pagerank": engine.pagerank,
        "harmonic": engine.harmonic_centrality,
        "katz": engine.katz_centrality,
    }

    func = algorithm_map.get(algorithm, engine.pagerank)
    result = func()

    return result.top_nodes[:top_k]
