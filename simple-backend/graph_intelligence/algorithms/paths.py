#!/usr/bin/env python3
"""
Graph Path Analysis Algorithms

Find connections and paths between entities in the graph.
Essential for threat intelligence pivoting and investigation.

Capabilities:
- Shortest path between two entities
- All paths up to a maximum depth
- Weighted shortest path (by confidence, risk, etc.)
- Path existence check
- Relationship type filtering
- Entity type filtering
"""

import heapq
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from ..models import (
    ExtendedEntityType,
    ExtendedRelationshipType,
    GraphNode,
    GraphEdge,
    PathResult,
)

logger = logging.getLogger(__name__)


# =============================================================================
# RESULT CLASSES
# =============================================================================

@dataclass
class PathInfo:
    """Detailed information about a single path."""
    path_id: str = ""
    source_id: str = ""
    target_id: str = ""
    length: int = 0
    node_ids: List[str] = field(default_factory=list)
    edge_ids: List[str] = field(default_factory=list)
    relationship_types: List[str] = field(default_factory=list)
    total_weight: float = 0.0
    total_confidence: float = 0.0
    min_confidence: float = 1.0
    nodes_data: List[Dict[str, Any]] = field(default_factory=list)
    edges_data: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "length": self.length,
            "node_ids": self.node_ids,
            "relationship_types": self.relationship_types,
            "total_weight": round(self.total_weight, 4),
            "total_confidence": round(self.total_confidence, 4),
            "min_confidence": round(self.min_confidence, 4),
            "nodes": self.nodes_data,
            "edges": self.edges_data,
        }


@dataclass
class MultiPathResult:
    """Result containing multiple paths."""
    source_id: str
    target_id: str
    paths_found: int = 0
    paths: List[PathInfo] = field(default_factory=list)
    shortest_length: int = 0
    computation_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "paths_found": self.paths_found,
            "shortest_length": self.shortest_length,
            "computation_time_ms": round(self.computation_time_ms, 2),
            "paths": [p.to_dict() for p in self.paths],
        }


@dataclass
class ReachabilityResult:
    """Result of reachability analysis."""
    source_id: str
    reachable_count: int = 0
    reachable_by_depth: Dict[int, int] = field(default_factory=dict)
    reachable_by_type: Dict[str, int] = field(default_factory=dict)
    reachable_ids: List[str] = field(default_factory=list)
    max_depth_reached: int = 0
    computation_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "reachable_count": self.reachable_count,
            "reachable_by_depth": self.reachable_by_depth,
            "reachable_by_type": self.reachable_by_type,
            "max_depth_reached": self.max_depth_reached,
            "computation_time_ms": round(self.computation_time_ms, 2),
        }


# =============================================================================
# PATH ENGINE
# =============================================================================

class PathEngine:
    """
    Engine for finding paths between entities in the graph.

    Supports various path-finding algorithms and filtering options.
    """

    def __init__(self, client=None):
        """
        Initialize the path engine.

        Args:
            client: Optional GraphClient for database access
        """
        self.client = client

        # Internal graph representation
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._adjacency: Dict[str, List[Tuple[str, GraphEdge]]] = {}
        self._reverse_adjacency: Dict[str, List[Tuple[str, GraphEdge]]] = {}

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
        self._adjacency = {n.entity_id: [] for n in nodes}
        self._reverse_adjacency = {n.entity_id: [] for n in nodes}

        for edge in edges:
            if edge.source_id in self._adjacency and edge.target_id in self._nodes:
                self._adjacency[edge.source_id].append((edge.target_id, edge))
                self._reverse_adjacency[edge.target_id].append((edge.source_id, edge))

                # Add reverse edge for bidirectional relationships
                if edge.bidirectional:
                    self._adjacency[edge.target_id].append((edge.source_id, edge))
                    self._reverse_adjacency[edge.source_id].append((edge.target_id, edge))

        logger.info(f"Built path graph with {len(self._nodes)} nodes, {len(self._edges)} edges")

    def build_from_client(
        self,
        investigation_id: str = None,
        entity_types: List[ExtendedEntityType] = None
    ) -> None:
        """
        Build graph from GraphClient data.

        Args:
            investigation_id: Filter by investigation
            entity_types: Filter by entity types
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
            stats = self.client.get_statistics()
            for entity_type in stats.nodes_by_type.keys():
                et = ExtendedEntityType.from_string(entity_type)
                nodes.extend(self.client.get_nodes_by_type(et, limit=10000))

        # Get edges
        node_ids = {n.entity_id for n in nodes}
        for node in nodes:
            node_edges = self.client.get_edges_for_node(node.entity_id, direction="out")
            for edge in node_edges:
                if edge.target_id in node_ids:
                    edges.append(edge)

        self.build_graph(nodes, edges)

    # =========================================================================
    # SHORTEST PATH
    # =========================================================================

    def shortest_path(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 6,
        relationship_types: List[ExtendedRelationshipType] = None,
        entity_types: List[ExtendedEntityType] = None,
        bidirectional_search: bool = True
    ) -> PathResult:
        """
        Find the shortest path between two entities.

        Args:
            source_id: Source entity ID
            target_id: Target entity ID
            max_depth: Maximum path length
            relationship_types: Filter by relationship types
            entity_types: Filter intermediate nodes by entity types
            bidirectional_search: Use bidirectional BFS (faster)

        Returns:
            PathResult with the shortest path
        """
        start_time = time.time()

        if source_id not in self._nodes or target_id not in self._nodes:
            return PathResult(
                found=False,
                source_id=source_id,
                target_id=target_id,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        if source_id == target_id:
            node = self._nodes[source_id]
            return PathResult(
                found=True,
                source_id=source_id,
                target_id=target_id,
                path_length=0,
                nodes=[self._node_to_dict(node)],
                edges=[],
                total_confidence=1.0,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        # Use bidirectional BFS for efficiency
        if bidirectional_search:
            path = self._bidirectional_bfs(
                source_id, target_id, max_depth,
                relationship_types, entity_types
            )
        else:
            path = self._bfs_path(
                source_id, target_id, max_depth,
                relationship_types, entity_types
            )

        computation_time = (time.time() - start_time) * 1000

        if path is None:
            return PathResult(
                found=False,
                source_id=source_id,
                target_id=target_id,
                computation_time_ms=computation_time,
            )

        # Build result
        nodes_data = []
        edges_data = []
        total_confidence = 1.0

        for i, node_id in enumerate(path["nodes"]):
            node = self._nodes.get(node_id)
            if node:
                nodes_data.append(self._node_to_dict(node))

        for edge in path["edges"]:
            edges_data.append(self._edge_to_dict(edge))
            total_confidence *= edge.confidence

        return PathResult(
            found=True,
            source_id=source_id,
            target_id=target_id,
            path_length=len(path["edges"]),
            nodes=nodes_data,
            edges=edges_data,
            total_confidence=total_confidence,
            computation_time_ms=computation_time,
        )

    def _bfs_path(
        self,
        source_id: str,
        target_id: str,
        max_depth: int,
        relationship_types: List[ExtendedRelationshipType],
        entity_types: List[ExtendedEntityType]
    ) -> Optional[Dict]:
        """Standard BFS for shortest path."""
        queue = deque([(source_id, [source_id], [])])
        visited = {source_id}

        while queue:
            current, path_nodes, path_edges = queue.popleft()

            if len(path_edges) >= max_depth:
                continue

            for neighbor_id, edge in self._adjacency.get(current, []):
                # Apply filters
                if not self._edge_passes_filter(edge, relationship_types):
                    continue
                if not self._node_passes_filter(neighbor_id, entity_types, is_intermediate=True):
                    continue

                if neighbor_id == target_id:
                    return {
                        "nodes": path_nodes + [neighbor_id],
                        "edges": path_edges + [edge],
                    }

                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    queue.append((
                        neighbor_id,
                        path_nodes + [neighbor_id],
                        path_edges + [edge]
                    ))

        return None

    def _bidirectional_bfs(
        self,
        source_id: str,
        target_id: str,
        max_depth: int,
        relationship_types: List[ExtendedRelationshipType],
        entity_types: List[ExtendedEntityType]
    ) -> Optional[Dict]:
        """Bidirectional BFS for faster shortest path."""
        # Forward search from source
        forward_visited = {source_id: (None, None)}  # node -> (parent, edge)
        forward_queue = deque([source_id])
        forward_depth = {source_id: 0}

        # Backward search from target
        backward_visited = {target_id: (None, None)}
        backward_queue = deque([target_id])
        backward_depth = {target_id: 0}

        meeting_node = None
        max_single_direction = max_depth // 2 + 1

        while forward_queue or backward_queue:
            # Expand forward
            if forward_queue:
                current = forward_queue.popleft()
                current_depth = forward_depth[current]

                if current_depth < max_single_direction:
                    for neighbor_id, edge in self._adjacency.get(current, []):
                        if not self._edge_passes_filter(edge, relationship_types):
                            continue
                        if not self._node_passes_filter(neighbor_id, entity_types, is_intermediate=True):
                            continue

                        if neighbor_id not in forward_visited:
                            forward_visited[neighbor_id] = (current, edge)
                            forward_depth[neighbor_id] = current_depth + 1
                            forward_queue.append(neighbor_id)

                            if neighbor_id in backward_visited:
                                meeting_node = neighbor_id
                                break

                if meeting_node:
                    break

            # Expand backward
            if backward_queue and not meeting_node:
                current = backward_queue.popleft()
                current_depth = backward_depth[current]

                if current_depth < max_single_direction:
                    for neighbor_id, edge in self._reverse_adjacency.get(current, []):
                        if not self._edge_passes_filter(edge, relationship_types):
                            continue
                        if not self._node_passes_filter(neighbor_id, entity_types, is_intermediate=True):
                            continue

                        if neighbor_id not in backward_visited:
                            backward_visited[neighbor_id] = (current, edge)
                            backward_depth[neighbor_id] = current_depth + 1
                            backward_queue.append(neighbor_id)

                            if neighbor_id in forward_visited:
                                meeting_node = neighbor_id
                                break

                if meeting_node:
                    break

        if not meeting_node:
            return None

        # Reconstruct path
        # Forward part: source -> meeting
        forward_path_nodes = []
        forward_path_edges = []
        node = meeting_node
        while node != source_id:
            forward_path_nodes.append(node)
            parent, edge = forward_visited[node]
            if edge:
                forward_path_edges.append(edge)
            node = parent
        forward_path_nodes.append(source_id)
        forward_path_nodes.reverse()
        forward_path_edges.reverse()

        # Backward part: meeting -> target
        backward_path_nodes = []
        backward_path_edges = []
        node = meeting_node
        while node != target_id:
            parent, edge = backward_visited[node]
            if parent:
                backward_path_nodes.append(parent)
            if edge:
                backward_path_edges.append(edge)
            node = parent

        # Combine (avoid duplicating meeting node)
        path_nodes = forward_path_nodes + backward_path_nodes
        path_edges = forward_path_edges + backward_path_edges

        return {
            "nodes": path_nodes,
            "edges": path_edges,
        }

    # =========================================================================
    # WEIGHTED SHORTEST PATH
    # =========================================================================

    def weighted_shortest_path(
        self,
        source_id: str,
        target_id: str,
        weight_function: Callable[[GraphEdge], float] = None,
        max_depth: int = 6,
        relationship_types: List[ExtendedRelationshipType] = None
    ) -> PathResult:
        """
        Find shortest path using edge weights (Dijkstra's algorithm).

        Args:
            source_id: Source entity ID
            target_id: Target entity ID
            weight_function: Function to compute edge weight (default: 1 - confidence)
            max_depth: Maximum path length
            relationship_types: Filter by relationship types

        Returns:
            PathResult with the weighted shortest path
        """
        start_time = time.time()

        if source_id not in self._nodes or target_id not in self._nodes:
            return PathResult(
                found=False,
                source_id=source_id,
                target_id=target_id,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        # Default weight: inverse of confidence (lower confidence = higher cost)
        if weight_function is None:
            weight_function = lambda e: 1.0 - e.confidence + 0.01

        # Dijkstra's algorithm
        distances = {source_id: 0.0}
        predecessors = {source_id: (None, None)}
        depths = {source_id: 0}
        heap = [(0.0, 0, source_id)]  # (distance, depth, node)
        visited = set()

        while heap:
            dist, depth, current = heapq.heappop(heap)

            if current in visited:
                continue
            visited.add(current)

            if current == target_id:
                break

            if depth >= max_depth:
                continue

            for neighbor_id, edge in self._adjacency.get(current, []):
                if neighbor_id in visited:
                    continue

                if not self._edge_passes_filter(edge, relationship_types):
                    continue

                weight = weight_function(edge)
                new_dist = dist + weight

                if neighbor_id not in distances or new_dist < distances[neighbor_id]:
                    distances[neighbor_id] = new_dist
                    predecessors[neighbor_id] = (current, edge)
                    depths[neighbor_id] = depth + 1
                    heapq.heappush(heap, (new_dist, depth + 1, neighbor_id))

        computation_time = (time.time() - start_time) * 1000

        if target_id not in predecessors:
            return PathResult(
                found=False,
                source_id=source_id,
                target_id=target_id,
                computation_time_ms=computation_time,
            )

        # Reconstruct path
        path_nodes = []
        path_edges = []
        node = target_id

        while node is not None:
            path_nodes.append(node)
            parent, edge = predecessors.get(node, (None, None))
            if edge:
                path_edges.append(edge)
            node = parent

        path_nodes.reverse()
        path_edges.reverse()

        # Build result
        nodes_data = [self._node_to_dict(self._nodes[nid]) for nid in path_nodes]
        edges_data = [self._edge_to_dict(e) for e in path_edges]
        total_confidence = 1.0
        for edge in path_edges:
            total_confidence *= edge.confidence

        return PathResult(
            found=True,
            source_id=source_id,
            target_id=target_id,
            path_length=len(path_edges),
            nodes=nodes_data,
            edges=edges_data,
            total_weight=distances[target_id],
            total_confidence=total_confidence,
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # ALL PATHS
    # =========================================================================

    def all_paths(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 4,
        max_paths: int = 20,
        relationship_types: List[ExtendedRelationshipType] = None,
        entity_types: List[ExtendedEntityType] = None
    ) -> MultiPathResult:
        """
        Find all paths between two entities up to a maximum depth.

        Args:
            source_id: Source entity ID
            target_id: Target entity ID
            max_depth: Maximum path length
            max_paths: Maximum number of paths to return
            relationship_types: Filter by relationship types
            entity_types: Filter intermediate nodes by entity types

        Returns:
            MultiPathResult with all found paths
        """
        start_time = time.time()

        if source_id not in self._nodes or target_id not in self._nodes:
            return MultiPathResult(
                source_id=source_id,
                target_id=target_id,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        paths = []
        shortest_length = float('inf')

        # DFS with path tracking
        def dfs(current: str, path_nodes: List[str], path_edges: List[GraphEdge], visited: Set[str]):
            nonlocal shortest_length

            if len(paths) >= max_paths:
                return

            if current == target_id:
                path_info = self._build_path_info(source_id, target_id, path_nodes, path_edges)
                paths.append(path_info)
                shortest_length = min(shortest_length, len(path_edges))
                return

            if len(path_edges) >= max_depth:
                return

            for neighbor_id, edge in self._adjacency.get(current, []):
                if neighbor_id in visited:
                    continue

                if not self._edge_passes_filter(edge, relationship_types):
                    continue
                if not self._node_passes_filter(neighbor_id, entity_types, is_intermediate=(neighbor_id != target_id)):
                    continue

                visited.add(neighbor_id)
                dfs(
                    neighbor_id,
                    path_nodes + [neighbor_id],
                    path_edges + [edge],
                    visited
                )
                visited.remove(neighbor_id)

        dfs(source_id, [source_id], [], {source_id})

        computation_time = (time.time() - start_time) * 1000

        # Sort paths by length, then by confidence
        paths.sort(key=lambda p: (p.length, -p.total_confidence))

        return MultiPathResult(
            source_id=source_id,
            target_id=target_id,
            paths_found=len(paths),
            paths=paths[:max_paths],
            shortest_length=int(shortest_length) if shortest_length != float('inf') else 0,
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # PATH EXISTS
    # =========================================================================

    def path_exists(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 6,
        relationship_types: List[ExtendedRelationshipType] = None
    ) -> bool:
        """
        Check if any path exists between two entities.

        Args:
            source_id: Source entity ID
            target_id: Target entity ID
            max_depth: Maximum path length
            relationship_types: Filter by relationship types

        Returns:
            True if a path exists, False otherwise
        """
        if source_id not in self._nodes or target_id not in self._nodes:
            return False

        if source_id == target_id:
            return True

        # Simple BFS check
        visited = {source_id}
        queue = deque([(source_id, 0)])

        while queue:
            current, depth = queue.popleft()

            if depth >= max_depth:
                continue

            for neighbor_id, edge in self._adjacency.get(current, []):
                if not self._edge_passes_filter(edge, relationship_types):
                    continue

                if neighbor_id == target_id:
                    return True

                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    queue.append((neighbor_id, depth + 1))

        return False

    # =========================================================================
    # REACHABILITY
    # =========================================================================

    def reachability(
        self,
        source_id: str,
        max_depth: int = 3,
        relationship_types: List[ExtendedRelationshipType] = None,
        entity_types: List[ExtendedEntityType] = None
    ) -> ReachabilityResult:
        """
        Find all entities reachable from a source within max_depth hops.

        Args:
            source_id: Source entity ID
            max_depth: Maximum depth to explore
            relationship_types: Filter by relationship types
            entity_types: Filter by entity types

        Returns:
            ReachabilityResult with reachable entities
        """
        start_time = time.time()

        if source_id not in self._nodes:
            return ReachabilityResult(
                source_id=source_id,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        reachable_ids = []
        reachable_by_depth = {}
        reachable_by_type = {}
        max_depth_reached = 0

        visited = {source_id}
        current_level = {source_id}

        for depth in range(1, max_depth + 1):
            next_level = set()
            depth_count = 0

            for node_id in current_level:
                for neighbor_id, edge in self._adjacency.get(node_id, []):
                    if neighbor_id in visited:
                        continue

                    if not self._edge_passes_filter(edge, relationship_types):
                        continue

                    neighbor = self._nodes.get(neighbor_id)
                    if not neighbor:
                        continue

                    if entity_types and neighbor.entity_type not in entity_types:
                        continue

                    visited.add(neighbor_id)
                    next_level.add(neighbor_id)
                    reachable_ids.append(neighbor_id)
                    depth_count += 1

                    # Count by type
                    type_str = neighbor.entity_type.value
                    reachable_by_type[type_str] = reachable_by_type.get(type_str, 0) + 1

            if depth_count > 0:
                reachable_by_depth[depth] = depth_count
                max_depth_reached = depth

            current_level = next_level

            if not next_level:
                break

        computation_time = (time.time() - start_time) * 1000

        return ReachabilityResult(
            source_id=source_id,
            reachable_count=len(reachable_ids),
            reachable_by_depth=reachable_by_depth,
            reachable_by_type=reachable_by_type,
            reachable_ids=reachable_ids,
            max_depth_reached=max_depth_reached,
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # COMMON NEIGHBORS
    # =========================================================================

    def common_neighbors(
        self,
        entity_id_a: str,
        entity_id_b: str,
        relationship_types: List[ExtendedRelationshipType] = None
    ) -> List[str]:
        """
        Find common neighbors of two entities.

        Args:
            entity_id_a: First entity ID
            entity_id_b: Second entity ID
            relationship_types: Filter by relationship types

        Returns:
            List of common neighbor entity IDs
        """
        if entity_id_a not in self._nodes or entity_id_b not in self._nodes:
            return []

        neighbors_a = set()
        neighbors_b = set()

        for neighbor_id, edge in self._adjacency.get(entity_id_a, []):
            if self._edge_passes_filter(edge, relationship_types):
                neighbors_a.add(neighbor_id)

        for neighbor_id, edge in self._reverse_adjacency.get(entity_id_a, []):
            if self._edge_passes_filter(edge, relationship_types):
                neighbors_a.add(neighbor_id)

        for neighbor_id, edge in self._adjacency.get(entity_id_b, []):
            if self._edge_passes_filter(edge, relationship_types):
                neighbors_b.add(neighbor_id)

        for neighbor_id, edge in self._reverse_adjacency.get(entity_id_b, []):
            if self._edge_passes_filter(edge, relationship_types):
                neighbors_b.add(neighbor_id)

        return list(neighbors_a & neighbors_b)

    # =========================================================================
    # K-HOP NEIGHBORS
    # =========================================================================

    def k_hop_neighbors(
        self,
        source_id: str,
        k: int = 2,
        relationship_types: List[ExtendedRelationshipType] = None,
        entity_types: List[ExtendedEntityType] = None
    ) -> Dict[int, List[str]]:
        """
        Get neighbors at exactly k hops from source.

        Args:
            source_id: Source entity ID
            k: Number of hops
            relationship_types: Filter by relationship types
            entity_types: Filter by entity types

        Returns:
            Dictionary mapping hop distance to list of entity IDs
        """
        if source_id not in self._nodes:
            return {}

        result = {}
        visited = {source_id}
        current_level = {source_id}

        for hop in range(1, k + 1):
            next_level = set()

            for node_id in current_level:
                for neighbor_id, edge in self._adjacency.get(node_id, []):
                    if neighbor_id in visited:
                        continue

                    if not self._edge_passes_filter(edge, relationship_types):
                        continue

                    neighbor = self._nodes.get(neighbor_id)
                    if not neighbor:
                        continue

                    if entity_types and neighbor.entity_type not in entity_types:
                        continue

                    visited.add(neighbor_id)
                    next_level.add(neighbor_id)

            if next_level:
                result[hop] = list(next_level)

            current_level = next_level

        return result

    # =========================================================================
    # PIVOT FINDING
    # =========================================================================

    def find_pivots(
        self,
        entity_ids: List[str],
        max_depth: int = 2
    ) -> List[Tuple[str, int]]:
        """
        Find entities that connect multiple given entities (pivot points).

        Args:
            entity_ids: List of entity IDs to find connections between
            max_depth: Maximum depth to search

        Returns:
            List of (entity_id, connection_count) tuples sorted by connections
        """
        if len(entity_ids) < 2:
            return []

        # Find all reachable entities from each source
        reachable_from = {}
        for entity_id in entity_ids:
            result = self.reachability(entity_id, max_depth=max_depth)
            reachable_from[entity_id] = set(result.reachable_ids)

        # Count how many source entities can reach each candidate
        pivot_counts = {}
        all_candidates = set()
        for reachable in reachable_from.values():
            all_candidates.update(reachable)

        for candidate in all_candidates:
            if candidate in entity_ids:
                continue  # Don't count source entities as pivots

            count = sum(1 for entity_id in entity_ids if candidate in reachable_from.get(entity_id, set()))
            if count >= 2:
                pivot_counts[candidate] = count

        # Sort by connection count
        return sorted(pivot_counts.items(), key=lambda x: x[1], reverse=True)

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    def _edge_passes_filter(
        self,
        edge: GraphEdge,
        relationship_types: List[ExtendedRelationshipType]
    ) -> bool:
        """Check if edge passes relationship type filter."""
        if relationship_types is None:
            return True
        return edge.relationship_type in relationship_types

    def _node_passes_filter(
        self,
        node_id: str,
        entity_types: List[ExtendedEntityType],
        is_intermediate: bool = True
    ) -> bool:
        """Check if node passes entity type filter."""
        if entity_types is None:
            return True

        node = self._nodes.get(node_id)
        if not node:
            return False

        return node.entity_type in entity_types

    def _node_to_dict(self, node: GraphNode) -> Dict[str, Any]:
        """Convert node to dictionary for results."""
        return {
            "entity_id": node.entity_id,
            "type": node.entity_type.value,
            "value": node.value,
            "label": node.label,
            "confidence": round(node.confidence, 3),
            "risk_score": round(node.risk_score, 1),
        }

    def _edge_to_dict(self, edge: GraphEdge) -> Dict[str, Any]:
        """Convert edge to dictionary for results."""
        return {
            "source_id": edge.source_id,
            "target_id": edge.target_id,
            "type": edge.relationship_type.value,
            "confidence": round(edge.confidence, 3),
            "weight": round(edge.weight, 3),
        }

    def _build_path_info(
        self,
        source_id: str,
        target_id: str,
        path_nodes: List[str],
        path_edges: List[GraphEdge]
    ) -> PathInfo:
        """Build PathInfo from path data."""
        import uuid

        total_confidence = 1.0
        min_confidence = 1.0
        total_weight = 0.0

        nodes_data = []
        edges_data = []
        relationship_types = []

        for node_id in path_nodes:
            node = self._nodes.get(node_id)
            if node:
                nodes_data.append(self._node_to_dict(node))

        for edge in path_edges:
            edges_data.append(self._edge_to_dict(edge))
            relationship_types.append(edge.relationship_type.value)
            total_confidence *= edge.confidence
            min_confidence = min(min_confidence, edge.confidence)
            total_weight += edge.weight

        return PathInfo(
            path_id=str(uuid.uuid4())[:8],
            source_id=source_id,
            target_id=target_id,
            length=len(path_edges),
            node_ids=path_nodes,
            edge_ids=[e.edge_id for e in path_edges],
            relationship_types=relationship_types,
            total_weight=total_weight,
            total_confidence=total_confidence,
            min_confidence=min_confidence,
            nodes_data=nodes_data,
            edges_data=edges_data,
        )

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

def find_shortest_path(
    nodes: List[GraphNode],
    edges: List[GraphEdge],
    source_id: str,
    target_id: str,
    max_depth: int = 6
) -> PathResult:
    """
    Find shortest path between two entities.

    Args:
        nodes: List of GraphNode objects
        edges: List of GraphEdge objects
        source_id: Source entity ID
        target_id: Target entity ID
        max_depth: Maximum path length

    Returns:
        PathResult with the shortest path
    """
    engine = PathEngine()
    engine.build_graph(nodes, edges)
    return engine.shortest_path(source_id, target_id, max_depth)


def find_all_paths(
    nodes: List[GraphNode],
    edges: List[GraphEdge],
    source_id: str,
    target_id: str,
    max_depth: int = 4,
    max_paths: int = 10
) -> MultiPathResult:
    """
    Find all paths between two entities.

    Args:
        nodes: List of GraphNode objects
        edges: List of GraphEdge objects
        source_id: Source entity ID
        target_id: Target entity ID
        max_depth: Maximum path length
        max_paths: Maximum paths to return

    Returns:
        MultiPathResult with all paths
    """
    engine = PathEngine()
    engine.build_graph(nodes, edges)
    return engine.all_paths(source_id, target_id, max_depth, max_paths)


def check_connection(
    nodes: List[GraphNode],
    edges: List[GraphEdge],
    source_id: str,
    target_id: str,
    max_depth: int = 6
) -> bool:
    """
    Check if two entities are connected.

    Args:
        nodes: List of GraphNode objects
        edges: List of GraphEdge objects
        source_id: Source entity ID
        target_id: Target entity ID
        max_depth: Maximum path length

    Returns:
        True if connected, False otherwise
    """
    engine = PathEngine()
    engine.build_graph(nodes, edges)
    return engine.path_exists(source_id, target_id, max_depth)
