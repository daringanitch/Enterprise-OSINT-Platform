#!/usr/bin/env python3
"""
Graph Community Detection Algorithms

Identify clusters and communities of related entities in the graph.
Essential for discovering threat actor infrastructure, campaign groupings,
and organizational structures.

Capabilities:
- Connected components (strongly/weakly)
- Louvain community detection
- Label propagation
- K-core decomposition
- Modularity calculation
- Clustering coefficient
"""

import logging
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models import (
    CommunityInfo,
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
class CommunityResult:
    """Result of community detection."""
    algorithm: str
    community_count: int
    modularity: float = 0.0
    coverage: float = 0.0
    communities: List[CommunityInfo] = field(default_factory=list)
    node_to_community: Dict[str, str] = field(default_factory=dict)
    computation_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "community_count": self.community_count,
            "modularity": round(self.modularity, 4),
            "coverage": round(self.coverage, 4),
            "computation_time_ms": round(self.computation_time_ms, 2),
            "communities": [c.to_dict() for c in self.communities],
            "largest_community_size": max((c.size for c in self.communities), default=0),
        }


@dataclass
class ComponentResult:
    """Result of connected component analysis."""
    component_type: str  # "strongly" or "weakly"
    component_count: int
    largest_size: int
    components: List[List[str]] = field(default_factory=list)
    size_distribution: Dict[int, int] = field(default_factory=dict)
    computation_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component_type": self.component_type,
            "component_count": self.component_count,
            "largest_size": self.largest_size,
            "size_distribution": self.size_distribution,
            "computation_time_ms": round(self.computation_time_ms, 2),
            "components": [comp[:20] for comp in self.components[:10]],  # Limit output
        }


@dataclass
class KCoreResult:
    """Result of k-core decomposition."""
    max_k: int
    core_numbers: Dict[str, int] = field(default_factory=dict)
    k_cores: Dict[int, List[str]] = field(default_factory=dict)
    degeneracy: int = 0
    computation_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_k": self.max_k,
            "degeneracy": self.degeneracy,
            "k_core_sizes": {k: len(v) for k, v in self.k_cores.items()},
            "computation_time_ms": round(self.computation_time_ms, 2),
        }


@dataclass
class ClusteringResult:
    """Result of clustering coefficient calculation."""
    global_clustering: float
    average_clustering: float
    node_clustering: Dict[str, float] = field(default_factory=dict)
    triangle_count: int = 0
    computation_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "global_clustering": round(self.global_clustering, 4),
            "average_clustering": round(self.average_clustering, 4),
            "triangle_count": self.triangle_count,
            "computation_time_ms": round(self.computation_time_ms, 2),
            "top_clustered_nodes": sorted(
                self.node_clustering.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
        }


# =============================================================================
# COMMUNITY ENGINE
# =============================================================================

class CommunityEngine:
    """
    Engine for detecting communities and clusters in the graph.

    Implements multiple algorithms for different use cases:
    - Louvain: Best for large graphs, finds natural communities
    - Label Propagation: Fast, good for semi-supervised scenarios
    - Connected Components: Basic structural analysis
    - K-Core: Find densely connected subgraphs
    """

    def __init__(self, client=None):
        """
        Initialize the community engine.

        Args:
            client: Optional GraphClient for database access
        """
        self.client = client

        # Internal graph representation
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._adjacency: Dict[str, Set[str]] = {}
        self._edge_weights: Dict[Tuple[str, str], float] = {}
        self._total_weight: float = 0.0

    # =========================================================================
    # GRAPH BUILDING
    # =========================================================================

    def build_graph(
        self,
        nodes: List[GraphNode],
        edges: List[GraphEdge]
    ) -> None:
        """
        Build internal graph representation.

        Args:
            nodes: List of GraphNode objects
            edges: List of GraphEdge objects
        """
        self._nodes = {n.entity_id: n for n in nodes}
        self._edges = edges
        self._adjacency = {n.entity_id: set() for n in nodes}
        self._edge_weights = {}
        self._total_weight = 0.0

        for edge in edges:
            if edge.source_id in self._adjacency and edge.target_id in self._nodes:
                # Treat as undirected for community detection
                self._adjacency[edge.source_id].add(edge.target_id)
                self._adjacency[edge.target_id].add(edge.source_id)

                # Store edge weight (use max if multiple edges)
                key = tuple(sorted([edge.source_id, edge.target_id]))
                weight = edge.composite_weight
                if key in self._edge_weights:
                    self._edge_weights[key] = max(self._edge_weights[key], weight)
                else:
                    self._edge_weights[key] = weight
                    self._total_weight += weight

        logger.info(f"Built community graph with {len(self._nodes)} nodes, "
                   f"{len(self._edge_weights)} unique edges")

    # =========================================================================
    # CONNECTED COMPONENTS
    # =========================================================================

    def weakly_connected_components(self) -> ComponentResult:
        """
        Find weakly connected components (treating graph as undirected).

        Returns:
            ComponentResult with component information
        """
        start_time = time.time()

        visited = set()
        components = []

        def bfs(start: str) -> List[str]:
            component = []
            queue = [start]
            visited.add(start)

            while queue:
                node = queue.pop(0)
                component.append(node)

                for neighbor in self._adjacency.get(node, set()):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)

            return component

        for node_id in self._nodes:
            if node_id not in visited:
                component = bfs(node_id)
                components.append(component)

        # Sort by size (largest first)
        components.sort(key=len, reverse=True)

        # Compute size distribution
        size_dist = defaultdict(int)
        for comp in components:
            size_dist[len(comp)] += 1

        computation_time = (time.time() - start_time) * 1000

        return ComponentResult(
            component_type="weakly",
            component_count=len(components),
            largest_size=len(components[0]) if components else 0,
            components=components,
            size_distribution=dict(size_dist),
            computation_time_ms=computation_time,
        )

    def strongly_connected_components(self) -> ComponentResult:
        """
        Find strongly connected components using Tarjan's algorithm.

        Returns:
            ComponentResult with component information
        """
        start_time = time.time()

        # Build directed adjacency
        directed_adj: Dict[str, Set[str]] = {n: set() for n in self._nodes}
        for edge in self._edges:
            if edge.source_id in directed_adj:
                directed_adj[edge.source_id].add(edge.target_id)

        # Tarjan's algorithm
        index_counter = [0]
        stack = []
        lowlink = {}
        index = {}
        on_stack = {}
        components = []

        def strongconnect(node: str):
            index[node] = index_counter[0]
            lowlink[node] = index_counter[0]
            index_counter[0] += 1
            stack.append(node)
            on_stack[node] = True

            for neighbor in directed_adj.get(node, set()):
                if neighbor not in index:
                    strongconnect(neighbor)
                    lowlink[node] = min(lowlink[node], lowlink[neighbor])
                elif on_stack.get(neighbor, False):
                    lowlink[node] = min(lowlink[node], index[neighbor])

            if lowlink[node] == index[node]:
                component = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    component.append(w)
                    if w == node:
                        break
                components.append(component)

        for node in self._nodes:
            if node not in index:
                strongconnect(node)

        # Sort by size
        components.sort(key=len, reverse=True)

        # Size distribution
        size_dist = defaultdict(int)
        for comp in components:
            size_dist[len(comp)] += 1

        computation_time = (time.time() - start_time) * 1000

        return ComponentResult(
            component_type="strongly",
            component_count=len(components),
            largest_size=len(components[0]) if components else 0,
            components=components,
            size_distribution=dict(size_dist),
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # LOUVAIN COMMUNITY DETECTION
    # =========================================================================

    def louvain(
        self,
        resolution: float = 1.0,
        max_iterations: int = 100,
        min_modularity_gain: float = 1e-7
    ) -> CommunityResult:
        """
        Louvain community detection algorithm.

        Optimizes modularity through local node moves and community aggregation.
        Excellent for finding natural community structure.

        Args:
            resolution: Resolution parameter (higher = smaller communities)
            max_iterations: Maximum iterations per phase
            min_modularity_gain: Minimum gain to continue

        Returns:
            CommunityResult with detected communities
        """
        start_time = time.time()

        if not self._nodes:
            return CommunityResult(
                algorithm="louvain",
                community_count=0,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        # Initialize: each node in its own community
        node_to_comm = {node: node for node in self._nodes}
        comm_to_nodes: Dict[str, Set[str]] = {node: {node} for node in self._nodes}

        # Compute initial degrees
        degrees = {node: sum(
            self._edge_weights.get(tuple(sorted([node, n])), 0)
            for n in self._adjacency.get(node, set())
        ) for node in self._nodes}

        total_weight = self._total_weight or 1.0

        def modularity_gain(node: str, target_comm: str, current_comm: str) -> float:
            """Calculate modularity gain from moving node to target community."""
            if target_comm == current_comm:
                return 0.0

            # Sum of weights to target community
            ki_in = sum(
                self._edge_weights.get(tuple(sorted([node, n])), 0)
                for n in comm_to_nodes.get(target_comm, set())
                if n != node
            )

            # Sum of weights to current community
            ki_out = sum(
                self._edge_weights.get(tuple(sorted([node, n])), 0)
                for n in comm_to_nodes.get(current_comm, set())
                if n != node
            )

            # Total weight in communities
            sigma_in = sum(degrees.get(n, 0) for n in comm_to_nodes.get(target_comm, set()))
            sigma_out = sum(degrees.get(n, 0) for n in comm_to_nodes.get(current_comm, set())) - degrees.get(node, 0)

            ki = degrees.get(node, 0)

            # Modularity gain formula
            gain = (ki_in - ki_out) / total_weight
            gain += resolution * ki * (sigma_out - sigma_in) / (2 * total_weight * total_weight)

            return gain

        # Phase 1: Local optimization
        improved = True
        iteration = 0

        while improved and iteration < max_iterations:
            improved = False
            iteration += 1

            # Shuffle nodes for randomization
            nodes_list = list(self._nodes.keys())
            random.shuffle(nodes_list)

            for node in nodes_list:
                current_comm = node_to_comm[node]
                best_comm = current_comm
                best_gain = 0.0

                # Check neighbors' communities
                neighbor_comms = set()
                for neighbor in self._adjacency.get(node, set()):
                    neighbor_comms.add(node_to_comm[neighbor])

                for target_comm in neighbor_comms:
                    if target_comm != current_comm:
                        gain = modularity_gain(node, target_comm, current_comm)
                        if gain > best_gain + min_modularity_gain:
                            best_gain = gain
                            best_comm = target_comm

                if best_comm != current_comm:
                    # Move node to new community
                    comm_to_nodes[current_comm].discard(node)
                    if not comm_to_nodes[current_comm]:
                        del comm_to_nodes[current_comm]

                    if best_comm not in comm_to_nodes:
                        comm_to_nodes[best_comm] = set()
                    comm_to_nodes[best_comm].add(node)
                    node_to_comm[node] = best_comm
                    improved = True

        # Build final communities
        communities = []
        for comm_id, members in comm_to_nodes.items():
            if members:
                community = self._build_community_info(
                    comm_id=comm_id,
                    member_ids=list(members)
                )
                communities.append(community)

        # Sort by size
        communities.sort(key=lambda c: c.size, reverse=True)

        # Calculate modularity
        modularity = self._calculate_modularity(node_to_comm, resolution)

        computation_time = (time.time() - start_time) * 1000

        return CommunityResult(
            algorithm="louvain",
            community_count=len(communities),
            modularity=modularity,
            coverage=len([c for c in communities if c.size > 1]) / max(len(communities), 1),
            communities=communities,
            node_to_community=node_to_comm,
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # LABEL PROPAGATION
    # =========================================================================

    def label_propagation(
        self,
        max_iterations: int = 100,
        seed: int = None
    ) -> CommunityResult:
        """
        Label propagation community detection.

        Fast algorithm where nodes adopt the most common label among neighbors.
        Good for large graphs and semi-supervised scenarios.

        Args:
            max_iterations: Maximum iterations
            seed: Random seed for reproducibility

        Returns:
            CommunityResult with detected communities
        """
        start_time = time.time()

        if seed is not None:
            random.seed(seed)

        if not self._nodes:
            return CommunityResult(
                algorithm="label_propagation",
                community_count=0,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        # Initialize: each node has its own label
        labels = {node: i for i, node in enumerate(self._nodes)}

        for iteration in range(max_iterations):
            changed = False
            nodes_list = list(self._nodes.keys())
            random.shuffle(nodes_list)

            for node in nodes_list:
                neighbors = self._adjacency.get(node, set())
                if not neighbors:
                    continue

                # Count neighbor labels (weighted)
                label_weights: Dict[int, float] = defaultdict(float)
                for neighbor in neighbors:
                    weight = self._edge_weights.get(
                        tuple(sorted([node, neighbor])), 1.0
                    )
                    label_weights[labels[neighbor]] += weight

                if label_weights:
                    # Find most common label(s)
                    max_weight = max(label_weights.values())
                    best_labels = [l for l, w in label_weights.items() if w == max_weight]

                    # Random tie-breaking
                    new_label = random.choice(best_labels)

                    if new_label != labels[node]:
                        labels[node] = new_label
                        changed = True

            if not changed:
                break

        # Group nodes by label
        label_to_nodes: Dict[int, List[str]] = defaultdict(list)
        for node, label in labels.items():
            label_to_nodes[label].append(node)

        # Build communities
        communities = []
        node_to_comm = {}
        for label, members in label_to_nodes.items():
            comm_id = f"lp_{label}"
            community = self._build_community_info(
                comm_id=comm_id,
                member_ids=members
            )
            communities.append(community)
            for member in members:
                node_to_comm[member] = comm_id

        # Sort by size
        communities.sort(key=lambda c: c.size, reverse=True)

        # Calculate modularity
        modularity = self._calculate_modularity(node_to_comm)

        computation_time = (time.time() - start_time) * 1000

        return CommunityResult(
            algorithm="label_propagation",
            community_count=len(communities),
            modularity=modularity,
            coverage=len([c for c in communities if c.size > 1]) / max(len(communities), 1),
            communities=communities,
            node_to_community=node_to_comm,
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # K-CORE DECOMPOSITION
    # =========================================================================

    def k_core_decomposition(self) -> KCoreResult:
        """
        K-core decomposition of the graph.

        A k-core is a maximal subgraph where every node has degree >= k.
        Useful for finding densely connected cores.

        Returns:
            KCoreResult with core numbers and k-cores
        """
        start_time = time.time()

        if not self._nodes:
            return KCoreResult(
                max_k=0,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        # Compute degrees
        degrees = {node: len(self._adjacency.get(node, set())) for node in self._nodes}

        # Initialize core numbers
        core_numbers = {node: 0 for node in self._nodes}

        # Create sorted list by degree
        nodes_by_degree = sorted(self._nodes.keys(), key=lambda n: degrees[n])
        remaining = set(self._nodes.keys())

        for node in nodes_by_degree:
            if node not in remaining:
                continue

            k = degrees[node]
            core_numbers[node] = k

            # Remove node and update neighbor degrees
            remaining.discard(node)
            for neighbor in self._adjacency.get(node, set()):
                if neighbor in remaining and degrees[neighbor] > k:
                    degrees[neighbor] -= 1

        # Group nodes by core number
        k_cores: Dict[int, List[str]] = defaultdict(list)
        for node, k in core_numbers.items():
            k_cores[k].append(node)

        max_k = max(core_numbers.values()) if core_numbers else 0

        computation_time = (time.time() - start_time) * 1000

        return KCoreResult(
            max_k=max_k,
            core_numbers=core_numbers,
            k_cores=dict(k_cores),
            degeneracy=max_k,
            computation_time_ms=computation_time,
        )

    def get_k_core(self, k: int) -> List[str]:
        """
        Get nodes in the k-core (nodes with core number >= k).

        Args:
            k: Core number threshold

        Returns:
            List of entity IDs in the k-core
        """
        result = self.k_core_decomposition()
        return [node for node, core_num in result.core_numbers.items() if core_num >= k]

    # =========================================================================
    # CLUSTERING COEFFICIENT
    # =========================================================================

    def clustering_coefficient(self) -> ClusteringResult:
        """
        Calculate clustering coefficients and count triangles.

        The clustering coefficient measures how connected a node's neighbors are.
        High clustering indicates tight-knit groups.

        Returns:
            ClusteringResult with clustering information
        """
        start_time = time.time()

        if not self._nodes:
            return ClusteringResult(
                global_clustering=0.0,
                average_clustering=0.0,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        node_clustering = {}
        total_triangles = 0
        total_triplets = 0

        for node in self._nodes:
            neighbors = list(self._adjacency.get(node, set()))
            k = len(neighbors)

            if k < 2:
                node_clustering[node] = 0.0
                continue

            # Count triangles (edges between neighbors)
            triangles = 0
            for i in range(len(neighbors)):
                for j in range(i + 1, len(neighbors)):
                    if neighbors[j] in self._adjacency.get(neighbors[i], set()):
                        triangles += 1

            # Local clustering coefficient
            possible_triangles = k * (k - 1) / 2
            node_clustering[node] = triangles / possible_triangles if possible_triangles > 0 else 0

            total_triangles += triangles
            total_triplets += possible_triangles

        # Global clustering (transitivity)
        global_clustering = total_triangles / total_triplets if total_triplets > 0 else 0

        # Average clustering
        avg_clustering = sum(node_clustering.values()) / len(node_clustering) if node_clustering else 0

        computation_time = (time.time() - start_time) * 1000

        return ClusteringResult(
            global_clustering=global_clustering,
            average_clustering=avg_clustering,
            node_clustering=node_clustering,
            triangle_count=total_triangles,
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # MODULARITY
    # =========================================================================

    def _calculate_modularity(
        self,
        node_to_comm: Dict[str, str],
        resolution: float = 1.0
    ) -> float:
        """
        Calculate modularity of a community assignment.

        Modularity measures how good a community partition is.
        Higher values indicate better community structure.

        Args:
            node_to_comm: Node to community mapping
            resolution: Resolution parameter

        Returns:
            Modularity score
        """
        if not self._nodes or self._total_weight == 0:
            return 0.0

        total_weight = self._total_weight
        modularity = 0.0

        # Compute degrees
        degrees = {node: sum(
            self._edge_weights.get(tuple(sorted([node, n])), 0)
            for n in self._adjacency.get(node, set())
        ) for node in self._nodes}

        # Sum over edges
        for (u, v), weight in self._edge_weights.items():
            if node_to_comm.get(u) == node_to_comm.get(v):
                modularity += weight - resolution * degrees[u] * degrees[v] / (2 * total_weight)

        modularity /= total_weight

        return modularity

    # =========================================================================
    # COMMUNITY DETECTION (AUTO-SELECT)
    # =========================================================================

    def detect_communities(
        self,
        algorithm: str = "louvain",
        **kwargs
    ) -> CommunityResult:
        """
        Detect communities using specified algorithm.

        Args:
            algorithm: Algorithm to use ("louvain", "label_propagation")
            **kwargs: Algorithm-specific parameters

        Returns:
            CommunityResult with detected communities
        """
        if algorithm == "louvain":
            return self.louvain(**kwargs)
        elif algorithm == "label_propagation":
            return self.label_propagation(**kwargs)
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    def _build_community_info(
        self,
        comm_id: str,
        member_ids: List[str]
    ) -> CommunityInfo:
        """Build CommunityInfo from member list."""
        # Count entity types
        type_dist: Dict[str, int] = defaultdict(int)
        for member_id in member_ids:
            node = self._nodes.get(member_id)
            if node:
                type_dist[node.entity_type.value] += 1

        # Calculate density
        internal_edges = 0
        member_set = set(member_ids)
        for member in member_ids:
            for neighbor in self._adjacency.get(member, set()):
                if neighbor in member_set:
                    internal_edges += 1
        internal_edges //= 2  # Each edge counted twice

        n = len(member_ids)
        max_edges = n * (n - 1) / 2 if n > 1 else 1
        density = internal_edges / max_edges if max_edges > 0 else 0

        # Find central nodes (highest internal degree)
        internal_degrees = {}
        for member in member_ids:
            internal_degrees[member] = len(
                self._adjacency.get(member, set()) & member_set
            )

        central_nodes = sorted(
            member_ids,
            key=lambda m: internal_degrees[m],
            reverse=True
        )[:5]

        # Find bridge nodes (connected to other communities)
        bridge_nodes = []
        for member in member_ids:
            external = self._adjacency.get(member, set()) - member_set
            if external:
                bridge_nodes.append(member)

        # Calculate risk score (average of member risk scores)
        risk_scores = []
        for member_id in member_ids:
            node = self._nodes.get(member_id)
            if node:
                risk_scores.append(node.risk_score)
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0

        # Generate label
        label = self._generate_community_label(member_ids)

        return CommunityInfo(
            community_id=comm_id,
            size=len(member_ids),
            density=density,
            modularity_contribution=0.0,  # Calculated separately
            member_ids=member_ids,
            entity_type_distribution=dict(type_dist),
            central_nodes=central_nodes,
            bridge_nodes=bridge_nodes[:5],
            risk_score=avg_risk,
            label=label,
        )

    def _generate_community_label(self, member_ids: List[str]) -> str:
        """Generate a descriptive label for a community."""
        # Count entity types
        type_counts: Dict[str, int] = defaultdict(int)
        for member_id in member_ids:
            node = self._nodes.get(member_id)
            if node:
                type_counts[node.entity_type.value] += 1

        if not type_counts:
            return f"Community ({len(member_ids)} nodes)"

        # Find dominant type
        dominant_type = max(type_counts.items(), key=lambda x: x[1])[0]

        if len(member_ids) <= 3:
            # For small communities, list values
            values = []
            for member_id in member_ids[:3]:
                node = self._nodes.get(member_id)
                if node:
                    values.append(node.value[:15])
            return ", ".join(values)

        return f"{dominant_type.replace('_', ' ').title()} cluster ({len(member_ids)})"

    @property
    def node_count(self) -> int:
        """Get number of nodes."""
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        """Get number of unique edges."""
        return len(self._edge_weights)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def detect_communities(
    nodes: List[GraphNode],
    edges: List[GraphEdge],
    algorithm: str = "louvain",
    **kwargs
) -> CommunityResult:
    """
    Detect communities in a graph.

    Args:
        nodes: List of GraphNode objects
        edges: List of GraphEdge objects
        algorithm: Algorithm to use
        **kwargs: Algorithm-specific parameters

    Returns:
        CommunityResult with detected communities
    """
    engine = CommunityEngine()
    engine.build_graph(nodes, edges)
    return engine.detect_communities(algorithm, **kwargs)


def find_connected_components(
    nodes: List[GraphNode],
    edges: List[GraphEdge],
    strong: bool = False
) -> ComponentResult:
    """
    Find connected components in a graph.

    Args:
        nodes: List of GraphNode objects
        edges: List of GraphEdge objects
        strong: Use strongly connected components

    Returns:
        ComponentResult with components
    """
    engine = CommunityEngine()
    engine.build_graph(nodes, edges)

    if strong:
        return engine.strongly_connected_components()
    return engine.weakly_connected_components()


def get_dense_core(
    nodes: List[GraphNode],
    edges: List[GraphEdge],
    k: int = 2
) -> List[str]:
    """
    Get the k-core (densely connected subgraph).

    Args:
        nodes: List of GraphNode objects
        edges: List of GraphEdge objects
        k: Core number threshold

    Returns:
        List of entity IDs in the k-core
    """
    engine = CommunityEngine()
    engine.build_graph(nodes, edges)
    return engine.get_k_core(k)
