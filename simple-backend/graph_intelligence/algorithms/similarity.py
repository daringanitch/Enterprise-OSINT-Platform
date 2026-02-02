#!/usr/bin/env python3
"""
Graph Similarity Algorithms

Find similar entities based on graph structure, neighborhoods, and attributes.
Essential for threat intelligence to identify related infrastructure,
similar attack patterns, and potential aliases.

Capabilities:
- Jaccard similarity (neighborhood overlap)
- Cosine similarity (attribute vectors)
- Adamic-Adar index (common neighbors weighted by rarity)
- SimRank (structural equivalence)
- Resource Allocation index
- Common neighbor analysis
"""

import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
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
class SimilarityScore:
    """Score between two entities."""
    entity_a: str
    entity_b: str
    score: float
    method: str
    common_neighbors: List[str] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_a": self.entity_a,
            "entity_b": self.entity_b,
            "score": round(self.score, 4),
            "method": self.method,
            "common_neighbors": self.common_neighbors[:10],
            "explanation": self.explanation,
        }


@dataclass
class SimilarityResult:
    """Result of similarity computation."""
    method: str
    query_entity: str
    similar_entities: List[SimilarityScore] = field(default_factory=list)
    computation_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "query_entity": self.query_entity,
            "result_count": len(self.similar_entities),
            "similar_entities": [s.to_dict() for s in self.similar_entities[:20]],
            "computation_time_ms": round(self.computation_time_ms, 2),
        }


@dataclass
class BulkSimilarityResult:
    """Result of bulk similarity computation."""
    method: str
    pair_count: int
    pairs: List[SimilarityScore] = field(default_factory=list)
    computation_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "pair_count": self.pair_count,
            "top_pairs": [p.to_dict() for p in self.pairs[:50]],
            "computation_time_ms": round(self.computation_time_ms, 2),
        }


# =============================================================================
# SIMILARITY ENGINE
# =============================================================================

class SimilarityEngine:
    """
    Engine for computing entity similarity in the graph.

    Implements multiple algorithms for different use cases:
    - Jaccard: Simple neighborhood overlap, good baseline
    - Adamic-Adar: Weights common neighbors by inverse log degree
    - Resource Allocation: Similar to AA but stronger penalty for high-degree
    - Cosine: Attribute-based similarity using feature vectors
    - SimRank: Recursive structural similarity
    """

    def __init__(self, client=None):
        """
        Initialize the similarity engine.

        Args:
            client: Optional GraphClient for database access
        """
        self.client = client

        # Internal graph representation
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._adjacency: Dict[str, Set[str]] = {}
        self._in_adjacency: Dict[str, Set[str]] = {}  # For directed graphs
        self._node_attributes: Dict[str, Dict[str, Any]] = {}

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
        self._in_adjacency = {n.entity_id: set() for n in nodes}
        self._node_attributes = {}

        for edge in edges:
            if edge.source_id in self._adjacency and edge.target_id in self._nodes:
                # Undirected view
                self._adjacency[edge.source_id].add(edge.target_id)
                self._adjacency[edge.target_id].add(edge.source_id)
                # Directed view
                self._in_adjacency[edge.target_id].add(edge.source_id)

        # Build attribute vectors for cosine similarity
        for node in nodes:
            self._node_attributes[node.entity_id] = self._extract_attributes(node)

        logger.info(f"Built similarity graph with {len(self._nodes)} nodes, "
                   f"{len(self._edges)} edges")

    def _extract_attributes(self, node: GraphNode) -> Dict[str, Any]:
        """Extract attribute vector from a node."""
        attrs = {
            "entity_type": node.entity_type.value,
            "risk_score": node.risk_score,
            "confidence": node.confidence,
            "degree": len(self._adjacency.get(node.entity_id, set())),
        }

        # Add property attributes
        if node.properties:
            for key, value in node.properties.items():
                if isinstance(value, (int, float, str, bool)):
                    attrs[f"prop_{key}"] = value

        # Add tags as binary features
        if node.tags:
            for tag in node.tags:
                attrs[f"tag_{tag}"] = 1

        return attrs

    # =========================================================================
    # JACCARD SIMILARITY
    # =========================================================================

    def jaccard_similarity(
        self,
        entity_a: str,
        entity_b: str
    ) -> float:
        """
        Compute Jaccard similarity between two entities.

        Jaccard = |N(a) ∩ N(b)| / |N(a) ∪ N(b)|

        Args:
            entity_a: First entity ID
            entity_b: Second entity ID

        Returns:
            Jaccard similarity score [0, 1]
        """
        neighbors_a = self._adjacency.get(entity_a, set())
        neighbors_b = self._adjacency.get(entity_b, set())

        # Remove each other from neighbor sets
        neighbors_a = neighbors_a - {entity_b}
        neighbors_b = neighbors_b - {entity_a}

        intersection = len(neighbors_a & neighbors_b)
        union = len(neighbors_a | neighbors_b)

        if union == 0:
            return 0.0

        return intersection / union

    def find_similar_jaccard(
        self,
        entity_id: str,
        top_k: int = 10,
        min_score: float = 0.0,
        same_type_only: bool = False
    ) -> SimilarityResult:
        """
        Find entities most similar to given entity using Jaccard.

        Args:
            entity_id: Query entity ID
            top_k: Number of results to return
            min_score: Minimum similarity threshold
            same_type_only: Only compare with same entity type

        Returns:
            SimilarityResult with ranked similar entities
        """
        start_time = time.time()

        if entity_id not in self._nodes:
            return SimilarityResult(
                method="jaccard",
                query_entity=entity_id,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        query_node = self._nodes[entity_id]
        query_neighbors = self._adjacency.get(entity_id, set())

        scores = []
        for other_id, other_node in self._nodes.items():
            if other_id == entity_id:
                continue

            if same_type_only and other_node.entity_type != query_node.entity_type:
                continue

            score = self.jaccard_similarity(entity_id, other_id)

            if score >= min_score:
                common = list(query_neighbors & self._adjacency.get(other_id, set()))
                scores.append(SimilarityScore(
                    entity_a=entity_id,
                    entity_b=other_id,
                    score=score,
                    method="jaccard",
                    common_neighbors=common,
                    explanation=f"{len(common)} common neighbors out of "
                               f"{len(query_neighbors | self._adjacency.get(other_id, set()))} total",
                ))

        # Sort by score descending
        scores.sort(key=lambda x: x.score, reverse=True)

        computation_time = (time.time() - start_time) * 1000

        return SimilarityResult(
            method="jaccard",
            query_entity=entity_id,
            similar_entities=scores[:top_k],
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # ADAMIC-ADAR INDEX
    # =========================================================================

    def adamic_adar(
        self,
        entity_a: str,
        entity_b: str
    ) -> float:
        """
        Compute Adamic-Adar index between two entities.

        AA = Σ 1/log(|N(z)|) for z in N(a) ∩ N(b)

        Weights common neighbors by inverse log of their degree.
        Rare common neighbors contribute more.

        Args:
            entity_a: First entity ID
            entity_b: Second entity ID

        Returns:
            Adamic-Adar score
        """
        neighbors_a = self._adjacency.get(entity_a, set()) - {entity_b}
        neighbors_b = self._adjacency.get(entity_b, set()) - {entity_a}
        common = neighbors_a & neighbors_b

        if not common:
            return 0.0

        score = 0.0
        for neighbor in common:
            degree = len(self._adjacency.get(neighbor, set()))
            if degree > 1:
                score += 1.0 / math.log(degree)

        return score

    def find_similar_adamic_adar(
        self,
        entity_id: str,
        top_k: int = 10,
        min_score: float = 0.0,
        same_type_only: bool = False
    ) -> SimilarityResult:
        """
        Find entities most similar using Adamic-Adar index.

        Args:
            entity_id: Query entity ID
            top_k: Number of results to return
            min_score: Minimum similarity threshold
            same_type_only: Only compare with same entity type

        Returns:
            SimilarityResult with ranked similar entities
        """
        start_time = time.time()

        if entity_id not in self._nodes:
            return SimilarityResult(
                method="adamic_adar",
                query_entity=entity_id,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        query_node = self._nodes[entity_id]
        query_neighbors = self._adjacency.get(entity_id, set())

        scores = []
        for other_id, other_node in self._nodes.items():
            if other_id == entity_id:
                continue

            if same_type_only and other_node.entity_type != query_node.entity_type:
                continue

            score = self.adamic_adar(entity_id, other_id)

            if score >= min_score:
                common = list(query_neighbors & self._adjacency.get(other_id, set()))
                scores.append(SimilarityScore(
                    entity_a=entity_id,
                    entity_b=other_id,
                    score=score,
                    method="adamic_adar",
                    common_neighbors=common,
                    explanation=f"Weighted sum of {len(common)} common neighbors",
                ))

        scores.sort(key=lambda x: x.score, reverse=True)

        computation_time = (time.time() - start_time) * 1000

        return SimilarityResult(
            method="adamic_adar",
            query_entity=entity_id,
            similar_entities=scores[:top_k],
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # RESOURCE ALLOCATION INDEX
    # =========================================================================

    def resource_allocation(
        self,
        entity_a: str,
        entity_b: str
    ) -> float:
        """
        Compute Resource Allocation index between two entities.

        RA = Σ 1/|N(z)| for z in N(a) ∩ N(b)

        Similar to Adamic-Adar but without log, giving stronger penalty
        to high-degree common neighbors.

        Args:
            entity_a: First entity ID
            entity_b: Second entity ID

        Returns:
            Resource Allocation score
        """
        neighbors_a = self._adjacency.get(entity_a, set()) - {entity_b}
        neighbors_b = self._adjacency.get(entity_b, set()) - {entity_a}
        common = neighbors_a & neighbors_b

        if not common:
            return 0.0

        score = 0.0
        for neighbor in common:
            degree = len(self._adjacency.get(neighbor, set()))
            if degree > 0:
                score += 1.0 / degree

        return score

    def find_similar_resource_allocation(
        self,
        entity_id: str,
        top_k: int = 10,
        min_score: float = 0.0,
        same_type_only: bool = False
    ) -> SimilarityResult:
        """
        Find entities most similar using Resource Allocation index.

        Args:
            entity_id: Query entity ID
            top_k: Number of results to return
            min_score: Minimum similarity threshold
            same_type_only: Only compare with same entity type

        Returns:
            SimilarityResult with ranked similar entities
        """
        start_time = time.time()

        if entity_id not in self._nodes:
            return SimilarityResult(
                method="resource_allocation",
                query_entity=entity_id,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        query_node = self._nodes[entity_id]
        query_neighbors = self._adjacency.get(entity_id, set())

        scores = []
        for other_id, other_node in self._nodes.items():
            if other_id == entity_id:
                continue

            if same_type_only and other_node.entity_type != query_node.entity_type:
                continue

            score = self.resource_allocation(entity_id, other_id)

            if score >= min_score:
                common = list(query_neighbors & self._adjacency.get(other_id, set()))
                scores.append(SimilarityScore(
                    entity_a=entity_id,
                    entity_b=other_id,
                    score=score,
                    method="resource_allocation",
                    common_neighbors=common,
                    explanation=f"Resource allocation from {len(common)} common neighbors",
                ))

        scores.sort(key=lambda x: x.score, reverse=True)

        computation_time = (time.time() - start_time) * 1000

        return SimilarityResult(
            method="resource_allocation",
            query_entity=entity_id,
            similar_entities=scores[:top_k],
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # COSINE SIMILARITY (ATTRIBUTE-BASED)
    # =========================================================================

    def cosine_similarity(
        self,
        entity_a: str,
        entity_b: str
    ) -> float:
        """
        Compute cosine similarity based on attribute vectors.

        Args:
            entity_a: First entity ID
            entity_b: Second entity ID

        Returns:
            Cosine similarity score [0, 1]
        """
        attrs_a = self._node_attributes.get(entity_a, {})
        attrs_b = self._node_attributes.get(entity_b, {})

        if not attrs_a or not attrs_b:
            return 0.0

        # Get all keys
        all_keys = set(attrs_a.keys()) | set(attrs_b.keys())

        # Build vectors (numeric values only)
        vec_a = []
        vec_b = []

        for key in all_keys:
            val_a = attrs_a.get(key, 0)
            val_b = attrs_b.get(key, 0)

            # Convert to numeric
            if isinstance(val_a, str):
                val_a = hash(val_a) % 1000 / 1000.0
            if isinstance(val_b, str):
                val_b = hash(val_b) % 1000 / 1000.0
            if isinstance(val_a, bool):
                val_a = 1.0 if val_a else 0.0
            if isinstance(val_b, bool):
                val_b = 1.0 if val_b else 0.0

            vec_a.append(float(val_a) if val_a else 0.0)
            vec_b.append(float(val_b) if val_b else 0.0)

        # Compute cosine similarity
        dot_product = sum(a * b for a, b in zip(vec_a, vec_b))
        norm_a = math.sqrt(sum(a * a for a in vec_a))
        norm_b = math.sqrt(sum(b * b for b in vec_b))

        if norm_a == 0 or norm_b == 0:
            return 0.0

        return dot_product / (norm_a * norm_b)

    def find_similar_cosine(
        self,
        entity_id: str,
        top_k: int = 10,
        min_score: float = 0.0,
        same_type_only: bool = False
    ) -> SimilarityResult:
        """
        Find entities most similar using cosine similarity on attributes.

        Args:
            entity_id: Query entity ID
            top_k: Number of results to return
            min_score: Minimum similarity threshold
            same_type_only: Only compare with same entity type

        Returns:
            SimilarityResult with ranked similar entities
        """
        start_time = time.time()

        if entity_id not in self._nodes:
            return SimilarityResult(
                method="cosine",
                query_entity=entity_id,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        query_node = self._nodes[entity_id]

        scores = []
        for other_id, other_node in self._nodes.items():
            if other_id == entity_id:
                continue

            if same_type_only and other_node.entity_type != query_node.entity_type:
                continue

            score = self.cosine_similarity(entity_id, other_id)

            if score >= min_score:
                scores.append(SimilarityScore(
                    entity_a=entity_id,
                    entity_b=other_id,
                    score=score,
                    method="cosine",
                    common_neighbors=[],
                    explanation=f"Attribute-based similarity",
                ))

        scores.sort(key=lambda x: x.score, reverse=True)

        computation_time = (time.time() - start_time) * 1000

        return SimilarityResult(
            method="cosine",
            query_entity=entity_id,
            similar_entities=scores[:top_k],
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # SIMRANK (STRUCTURAL SIMILARITY)
    # =========================================================================

    def simrank(
        self,
        max_iterations: int = 10,
        decay: float = 0.8,
        threshold: float = 0.001
    ) -> Dict[Tuple[str, str], float]:
        """
        Compute SimRank similarity for all node pairs.

        SimRank: Two nodes are similar if they are connected to similar nodes.
        Uses iterative computation until convergence.

        Args:
            max_iterations: Maximum iterations
            decay: Decay factor (0-1)
            threshold: Convergence threshold

        Returns:
            Dictionary mapping (entity_a, entity_b) to similarity score
        """
        start_time = time.time()

        nodes = list(self._nodes.keys())
        n = len(nodes)

        if n == 0:
            return {}

        # Initialize: sim(a,a) = 1, sim(a,b) = 0
        sim = {}
        for i, a in enumerate(nodes):
            for j, b in enumerate(nodes):
                if i <= j:
                    key = (a, b) if a <= b else (b, a)
                    sim[key] = 1.0 if a == b else 0.0

        # Iterate
        for iteration in range(max_iterations):
            new_sim = {}
            max_diff = 0.0

            for i, a in enumerate(nodes):
                for j, b in enumerate(nodes):
                    if i > j:
                        continue

                    key = (a, b) if a <= b else (b, a)

                    if a == b:
                        new_sim[key] = 1.0
                        continue

                    # Get in-neighbors
                    in_a = self._in_adjacency.get(a, set())
                    in_b = self._in_adjacency.get(b, set())

                    if not in_a or not in_b:
                        new_sim[key] = 0.0
                        continue

                    # Sum similarity of in-neighbors
                    total = 0.0
                    for na in in_a:
                        for nb in in_b:
                            nkey = (na, nb) if na <= nb else (nb, na)
                            total += sim.get(nkey, 0.0)

                    new_val = decay * total / (len(in_a) * len(in_b))
                    new_sim[key] = new_val
                    max_diff = max(max_diff, abs(new_val - sim.get(key, 0.0)))

            sim = new_sim

            if max_diff < threshold:
                logger.info(f"SimRank converged at iteration {iteration + 1}")
                break

        logger.info(f"SimRank completed in {(time.time() - start_time) * 1000:.2f}ms")

        return sim

    def find_similar_simrank(
        self,
        entity_id: str,
        top_k: int = 10,
        min_score: float = 0.0,
        precomputed: Dict[Tuple[str, str], float] = None
    ) -> SimilarityResult:
        """
        Find entities most similar using SimRank.

        Args:
            entity_id: Query entity ID
            top_k: Number of results to return
            min_score: Minimum similarity threshold
            precomputed: Pre-computed SimRank scores (optional)

        Returns:
            SimilarityResult with ranked similar entities
        """
        start_time = time.time()

        if entity_id not in self._nodes:
            return SimilarityResult(
                method="simrank",
                query_entity=entity_id,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        # Compute SimRank if not provided
        if precomputed is None:
            precomputed = self.simrank()

        scores = []
        for other_id in self._nodes:
            if other_id == entity_id:
                continue

            key = (entity_id, other_id) if entity_id <= other_id else (other_id, entity_id)
            score = precomputed.get(key, 0.0)

            if score >= min_score:
                scores.append(SimilarityScore(
                    entity_a=entity_id,
                    entity_b=other_id,
                    score=score,
                    method="simrank",
                    common_neighbors=[],
                    explanation="Structural similarity based on neighbor patterns",
                ))

        scores.sort(key=lambda x: x.score, reverse=True)

        computation_time = (time.time() - start_time) * 1000

        return SimilarityResult(
            method="simrank",
            query_entity=entity_id,
            similar_entities=scores[:top_k],
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # BULK SIMILARITY COMPUTATION
    # =========================================================================

    def compute_all_pairs(
        self,
        method: str = "jaccard",
        min_score: float = 0.1,
        same_type_only: bool = False
    ) -> BulkSimilarityResult:
        """
        Compute similarity for all entity pairs above threshold.

        Args:
            method: Similarity method ("jaccard", "adamic_adar", "resource_allocation", "cosine")
            min_score: Minimum similarity threshold
            same_type_only: Only compare entities of same type

        Returns:
            BulkSimilarityResult with all similar pairs
        """
        start_time = time.time()

        # Select method
        method_func = {
            "jaccard": self.jaccard_similarity,
            "adamic_adar": self.adamic_adar,
            "resource_allocation": self.resource_allocation,
            "cosine": self.cosine_similarity,
        }.get(method, self.jaccard_similarity)

        nodes = list(self._nodes.keys())
        pairs = []

        for i, node_a in enumerate(nodes):
            for node_b in nodes[i + 1:]:
                # Check type constraint
                if same_type_only:
                    if self._nodes[node_a].entity_type != self._nodes[node_b].entity_type:
                        continue

                score = method_func(node_a, node_b)

                if score >= min_score:
                    common = list(
                        self._adjacency.get(node_a, set()) &
                        self._adjacency.get(node_b, set())
                    )
                    pairs.append(SimilarityScore(
                        entity_a=node_a,
                        entity_b=node_b,
                        score=score,
                        method=method,
                        common_neighbors=common,
                    ))

        # Sort by score descending
        pairs.sort(key=lambda x: x.score, reverse=True)

        computation_time = (time.time() - start_time) * 1000

        return BulkSimilarityResult(
            method=method,
            pair_count=len(pairs),
            pairs=pairs,
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # TYPE-SPECIFIC SIMILARITY
    # =========================================================================

    def find_similar_infrastructure(
        self,
        entity_id: str,
        top_k: int = 10
    ) -> SimilarityResult:
        """
        Find similar infrastructure entities (IPs, domains, etc.).

        Uses a combination of structural and attribute similarity
        optimized for infrastructure analysis.

        Args:
            entity_id: Query entity ID
            top_k: Number of results to return

        Returns:
            SimilarityResult with similar infrastructure
        """
        start_time = time.time()

        if entity_id not in self._nodes:
            return SimilarityResult(
                method="infrastructure",
                query_entity=entity_id,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        query_node = self._nodes[entity_id]

        # Infrastructure types
        infra_types = {
            ExtendedEntityType.IP_ADDRESS,
            ExtendedEntityType.DOMAIN,
            ExtendedEntityType.URL,
            ExtendedEntityType.ASN,
            ExtendedEntityType.CERTIFICATE,
        }

        # Filter to infrastructure nodes
        infra_nodes = [
            nid for nid, node in self._nodes.items()
            if node.entity_type in infra_types and nid != entity_id
        ]

        scores = []
        for other_id in infra_nodes:
            # Weighted combination of methods
            jaccard = self.jaccard_similarity(entity_id, other_id)
            aa = self.adamic_adar(entity_id, other_id)
            cosine = self.cosine_similarity(entity_id, other_id)

            # Normalize AA (can be > 1)
            aa_norm = min(aa / 5.0, 1.0) if aa > 0 else 0.0

            # Combined score
            combined = 0.4 * jaccard + 0.3 * aa_norm + 0.3 * cosine

            if combined > 0.01:
                common = list(
                    self._adjacency.get(entity_id, set()) &
                    self._adjacency.get(other_id, set())
                )
                scores.append(SimilarityScore(
                    entity_a=entity_id,
                    entity_b=other_id,
                    score=combined,
                    method="infrastructure",
                    common_neighbors=common,
                    explanation=f"Jaccard={jaccard:.2f}, AA={aa:.2f}, Cosine={cosine:.2f}",
                ))

        scores.sort(key=lambda x: x.score, reverse=True)

        computation_time = (time.time() - start_time) * 1000

        return SimilarityResult(
            method="infrastructure",
            query_entity=entity_id,
            similar_entities=scores[:top_k],
            computation_time_ms=computation_time,
        )

    def find_similar_threat_actors(
        self,
        entity_id: str,
        top_k: int = 10
    ) -> SimilarityResult:
        """
        Find similar threat actors based on TTPs and infrastructure.

        Args:
            entity_id: Query threat actor ID
            top_k: Number of results to return

        Returns:
            SimilarityResult with similar threat actors
        """
        start_time = time.time()

        if entity_id not in self._nodes:
            return SimilarityResult(
                method="threat_actor",
                query_entity=entity_id,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        query_node = self._nodes[entity_id]

        # Threat-related types
        threat_types = {
            ExtendedEntityType.THREAT_ACTOR,
            ExtendedEntityType.CAMPAIGN,
            ExtendedEntityType.INTRUSION_SET,
        }

        # Filter to threat actor nodes
        threat_nodes = [
            nid for nid, node in self._nodes.items()
            if node.entity_type in threat_types and nid != entity_id
        ]

        scores = []
        for other_id in threat_nodes:
            # For threat actors, structural similarity is key
            jaccard = self.jaccard_similarity(entity_id, other_id)
            ra = self.resource_allocation(entity_id, other_id)

            # Normalize RA
            ra_norm = min(ra, 1.0)

            # Combined score emphasizing structural patterns
            combined = 0.6 * jaccard + 0.4 * ra_norm

            if combined > 0.01:
                common = list(
                    self._adjacency.get(entity_id, set()) &
                    self._adjacency.get(other_id, set())
                )

                # Classify common neighbors
                common_infra = []
                common_malware = []
                for cn in common:
                    cn_node = self._nodes.get(cn)
                    if cn_node:
                        if cn_node.entity_type in {ExtendedEntityType.IP_ADDRESS, ExtendedEntityType.DOMAIN}:
                            common_infra.append(cn)
                        elif cn_node.entity_type == ExtendedEntityType.MALWARE_FAMILY:
                            common_malware.append(cn)

                scores.append(SimilarityScore(
                    entity_a=entity_id,
                    entity_b=other_id,
                    score=combined,
                    method="threat_actor",
                    common_neighbors=common,
                    explanation=f"Shared: {len(common_infra)} infra, {len(common_malware)} malware",
                ))

        scores.sort(key=lambda x: x.score, reverse=True)

        computation_time = (time.time() - start_time) * 1000

        return SimilarityResult(
            method="threat_actor",
            query_entity=entity_id,
            similar_entities=scores[:top_k],
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # GENERAL FIND SIMILAR
    # =========================================================================

    def find_similar(
        self,
        entity_id: str,
        method: str = "jaccard",
        top_k: int = 10,
        min_score: float = 0.0,
        same_type_only: bool = False,
        **kwargs
    ) -> SimilarityResult:
        """
        Find similar entities using specified method.

        Args:
            entity_id: Query entity ID
            method: Similarity method
            top_k: Number of results to return
            min_score: Minimum similarity threshold
            same_type_only: Only compare with same entity type
            **kwargs: Method-specific parameters

        Returns:
            SimilarityResult with ranked similar entities
        """
        method_map = {
            "jaccard": self.find_similar_jaccard,
            "adamic_adar": self.find_similar_adamic_adar,
            "resource_allocation": self.find_similar_resource_allocation,
            "cosine": self.find_similar_cosine,
            "simrank": self.find_similar_simrank,
            "infrastructure": self.find_similar_infrastructure,
            "threat_actor": self.find_similar_threat_actors,
        }

        func = method_map.get(method, self.find_similar_jaccard)

        # Handle different signatures
        if method in ["infrastructure", "threat_actor"]:
            return func(entity_id, top_k=top_k)
        elif method == "simrank":
            return func(entity_id, top_k=top_k, min_score=min_score, **kwargs)
        else:
            return func(entity_id, top_k=top_k, min_score=min_score, same_type_only=same_type_only)

    # =========================================================================
    # PROPERTIES
    # =========================================================================

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

def find_similar_entities(
    nodes: List[GraphNode],
    edges: List[GraphEdge],
    entity_id: str,
    method: str = "jaccard",
    top_k: int = 10,
    **kwargs
) -> SimilarityResult:
    """
    Find entities similar to given entity.

    Args:
        nodes: List of GraphNode objects
        edges: List of GraphEdge objects
        entity_id: Query entity ID
        method: Similarity method
        top_k: Number of results
        **kwargs: Additional parameters

    Returns:
        SimilarityResult with similar entities
    """
    engine = SimilarityEngine()
    engine.build_graph(nodes, edges)
    return engine.find_similar(entity_id, method=method, top_k=top_k, **kwargs)


def compute_pairwise_similarity(
    nodes: List[GraphNode],
    edges: List[GraphEdge],
    method: str = "jaccard",
    min_score: float = 0.1
) -> BulkSimilarityResult:
    """
    Compute similarity for all entity pairs.

    Args:
        nodes: List of GraphNode objects
        edges: List of GraphEdge objects
        method: Similarity method
        min_score: Minimum threshold

    Returns:
        BulkSimilarityResult with all similar pairs
    """
    engine = SimilarityEngine()
    engine.build_graph(nodes, edges)
    return engine.compute_all_pairs(method=method, min_score=min_score)
