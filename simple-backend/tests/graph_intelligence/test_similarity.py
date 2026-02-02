#!/usr/bin/env python3
"""
Tests for Graph Intelligence Similarity Algorithms

Tests Jaccard, Adamic-Adar, Resource Allocation, Cosine,
and SimRank similarity algorithms.
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from graph_intelligence.models import (
    GraphNode,
    GraphEdge,
    ExtendedEntityType,
    ExtendedRelationshipType,
)
from graph_intelligence.algorithms.similarity import (
    SimilarityEngine,
    SimilarityScore,
    SimilarityResult,
    BulkSimilarityResult,
    find_similar_entities,
    compute_pairwise_similarity,
)


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def simple_graph():
    """Simple graph for basic similarity tests."""
    # A1 and A2 share neighbors B1, B2
    # A3 shares only B1 with A1
    nodes = [
        GraphNode(entity_id="A1", entity_type=ExtendedEntityType.IP_ADDRESS, value="10.0.0.1"),
        GraphNode(entity_id="A2", entity_type=ExtendedEntityType.IP_ADDRESS, value="10.0.0.2"),
        GraphNode(entity_id="A3", entity_type=ExtendedEntityType.IP_ADDRESS, value="10.0.0.3"),
        GraphNode(entity_id="B1", entity_type=ExtendedEntityType.DOMAIN, value="shared1.com"),
        GraphNode(entity_id="B2", entity_type=ExtendedEntityType.DOMAIN, value="shared2.com"),
        GraphNode(entity_id="B3", entity_type=ExtendedEntityType.DOMAIN, value="unique.com"),
    ]

    edges = [
        # A1 connects to B1, B2
        GraphEdge(source_id="A1", target_id="B1", relationship_type=ExtendedRelationshipType.RESOLVES_TO, weight=1.0),
        GraphEdge(source_id="A1", target_id="B2", relationship_type=ExtendedRelationshipType.RESOLVES_TO, weight=1.0),
        # A2 connects to B1, B2 (same as A1)
        GraphEdge(source_id="A2", target_id="B1", relationship_type=ExtendedRelationshipType.RESOLVES_TO, weight=1.0),
        GraphEdge(source_id="A2", target_id="B2", relationship_type=ExtendedRelationshipType.RESOLVES_TO, weight=1.0),
        # A3 connects to B1 only
        GraphEdge(source_id="A3", target_id="B1", relationship_type=ExtendedRelationshipType.RESOLVES_TO, weight=1.0),
        # A3 also connects to unique B3
        GraphEdge(source_id="A3", target_id="B3", relationship_type=ExtendedRelationshipType.RESOLVES_TO, weight=1.0),
    ]

    return nodes, edges


@pytest.fixture
def threat_graph():
    """Realistic threat graph with infrastructure sharing."""
    nodes = [
        # Threat actors
        GraphNode(entity_id="TA1", entity_type=ExtendedEntityType.THREAT_ACTOR, value="APT28", risk_score=0.95),
        GraphNode(entity_id="TA2", entity_type=ExtendedEntityType.THREAT_ACTOR, value="APT29", risk_score=0.9),
        GraphNode(entity_id="TA3", entity_type=ExtendedEntityType.THREAT_ACTOR, value="Lazarus", risk_score=0.92),
        # Shared malware
        GraphNode(entity_id="MW1", entity_type=ExtendedEntityType.MALWARE_FAMILY, value="Zebrocy", risk_score=0.85),
        GraphNode(entity_id="MW2", entity_type=ExtendedEntityType.MALWARE_FAMILY, value="Mimikatz", risk_score=0.8),
        # Infrastructure
        GraphNode(entity_id="IP1", entity_type=ExtendedEntityType.IP_ADDRESS, value="185.99.133.72", risk_score=0.85),
        GraphNode(entity_id="IP2", entity_type=ExtendedEntityType.IP_ADDRESS, value="185.99.133.73", risk_score=0.85),
        GraphNode(entity_id="IP3", entity_type=ExtendedEntityType.IP_ADDRESS, value="45.77.100.1", risk_score=0.75),
        GraphNode(entity_id="DOM1", entity_type=ExtendedEntityType.DOMAIN, value="evil1.com", risk_score=0.8),
        GraphNode(entity_id="DOM2", entity_type=ExtendedEntityType.DOMAIN, value="evil2.com", risk_score=0.8),
    ]

    edges = [
        # TA1 uses MW1, MW2 and IP1, DOM1
        GraphEdge(source_id="TA1", target_id="MW1", relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO, weight=0.9),
        GraphEdge(source_id="TA1", target_id="MW2", relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO, weight=0.8),
        GraphEdge(source_id="TA1", target_id="IP1", relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO, weight=0.85),
        GraphEdge(source_id="TA1", target_id="DOM1", relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO, weight=0.85),
        # TA2 uses MW1, MW2 and IP2 (shares malware with TA1)
        GraphEdge(source_id="TA2", target_id="MW1", relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO, weight=0.85),
        GraphEdge(source_id="TA2", target_id="MW2", relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO, weight=0.75),
        GraphEdge(source_id="TA2", target_id="IP2", relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO, weight=0.8),
        GraphEdge(source_id="TA2", target_id="DOM2", relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO, weight=0.8),
        # TA3 uses different infrastructure (less similar)
        GraphEdge(source_id="TA3", target_id="IP3", relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO, weight=0.9),
        # Infrastructure connections
        GraphEdge(source_id="IP1", target_id="IP2", relationship_type=ExtendedRelationshipType.COLOCATED_WITH, weight=0.9),
        GraphEdge(source_id="IP1", target_id="DOM1", relationship_type=ExtendedRelationshipType.HOSTS, weight=0.95),
        GraphEdge(source_id="IP2", target_id="DOM2", relationship_type=ExtendedRelationshipType.HOSTS, weight=0.95),
    ]

    return nodes, edges


@pytest.fixture
def attribute_graph():
    """Graph with varied node attributes for cosine similarity testing."""
    nodes = [
        GraphNode(
            entity_id="N1", entity_type=ExtendedEntityType.IP_ADDRESS, value="1.1.1.1",
            risk_score=0.8, confidence=0.9, tags=["malicious", "c2"]
        ),
        GraphNode(
            entity_id="N2", entity_type=ExtendedEntityType.IP_ADDRESS, value="1.1.1.2",
            risk_score=0.85, confidence=0.85, tags=["malicious", "c2"]
        ),
        GraphNode(
            entity_id="N3", entity_type=ExtendedEntityType.DOMAIN, value="safe.com",
            risk_score=0.1, confidence=0.95, tags=["legitimate"]
        ),
    ]

    edges = [
        GraphEdge(source_id="N1", target_id="N2", relationship_type=ExtendedRelationshipType.COLOCATED_WITH, weight=0.9),
    ]

    return nodes, edges


# =============================================================================
# JACCARD SIMILARITY TESTS
# =============================================================================

class TestJaccardSimilarity:
    """Tests for Jaccard similarity."""

    def test_jaccard_identical_neighbors(self, simple_graph):
        """Test Jaccard with identical neighbors."""
        nodes, edges = simple_graph
        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        # A1 and A2 have identical neighbors (B1, B2)
        score = engine.jaccard_similarity("A1", "A2")

        # Should be 1.0 (perfect overlap)
        assert score == 1.0

    def test_jaccard_partial_overlap(self, simple_graph):
        """Test Jaccard with partial neighbor overlap."""
        nodes, edges = simple_graph
        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        # A1 has {B1, B2}, A3 has {B1, B3}
        # Intersection = {B1}, Union = {B1, B2, B3}
        score = engine.jaccard_similarity("A1", "A3")

        # Should be 1/3 = 0.333...
        assert 0.3 <= score <= 0.35

    def test_jaccard_no_overlap(self):
        """Test Jaccard with no neighbor overlap."""
        nodes = [
            GraphNode(entity_id="A", entity_type=ExtendedEntityType.IP_ADDRESS, value="1.1.1.1"),
            GraphNode(entity_id="B", entity_type=ExtendedEntityType.IP_ADDRESS, value="2.2.2.2"),
            GraphNode(entity_id="C", entity_type=ExtendedEntityType.DOMAIN, value="a.com"),
            GraphNode(entity_id="D", entity_type=ExtendedEntityType.DOMAIN, value="b.com"),
        ]
        edges = [
            GraphEdge(source_id="A", target_id="C", relationship_type=ExtendedRelationshipType.RESOLVES_TO, weight=1.0),
            GraphEdge(source_id="B", target_id="D", relationship_type=ExtendedRelationshipType.RESOLVES_TO, weight=1.0),
        ]

        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        score = engine.jaccard_similarity("A", "B")
        assert score == 0.0

    def test_find_similar_jaccard(self, simple_graph):
        """Test finding similar entities with Jaccard."""
        nodes, edges = simple_graph
        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        result = engine.find_similar_jaccard("A1", top_k=5)

        assert isinstance(result, SimilarityResult)
        assert result.method == "jaccard"
        assert result.query_entity == "A1"
        assert len(result.similar_entities) > 0

        # A2 should be most similar to A1
        top_match = result.similar_entities[0]
        assert top_match.entity_b == "A2"
        assert top_match.score == 1.0


# =============================================================================
# ADAMIC-ADAR TESTS
# =============================================================================

class TestAdamicAdar:
    """Tests for Adamic-Adar index."""

    def test_adamic_adar_basic(self, simple_graph):
        """Test Adamic-Adar computation."""
        nodes, edges = simple_graph
        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        score = engine.adamic_adar("A1", "A2")

        # Should be positive (they share B1, B2)
        assert score > 0

    def test_adamic_adar_weights_by_degree(self, simple_graph):
        """Test that AA weights by inverse log degree."""
        nodes, edges = simple_graph
        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        # A1-A2 share B1 (degree 3) and B2 (degree 2)
        # A1-A3 share B1 (degree 3) only
        aa_12 = engine.adamic_adar("A1", "A2")
        aa_13 = engine.adamic_adar("A1", "A3")

        # A1-A2 should have higher AA (more shared neighbors)
        assert aa_12 > aa_13

    def test_find_similar_adamic_adar(self, threat_graph):
        """Test finding similar with Adamic-Adar."""
        nodes, edges = threat_graph
        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        result = engine.find_similar_adamic_adar("TA1", top_k=5)

        assert result.method == "adamic_adar"
        assert len(result.similar_entities) > 0


# =============================================================================
# RESOURCE ALLOCATION TESTS
# =============================================================================

class TestResourceAllocation:
    """Tests for Resource Allocation index."""

    def test_resource_allocation_basic(self, simple_graph):
        """Test Resource Allocation computation."""
        nodes, edges = simple_graph
        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        score = engine.resource_allocation("A1", "A2")

        # Should be positive
        assert score > 0

    def test_resource_allocation_vs_adamic_adar(self, simple_graph):
        """Test that RA penalizes high-degree more than AA."""
        nodes, edges = simple_graph
        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        aa = engine.adamic_adar("A1", "A2")
        ra = engine.resource_allocation("A1", "A2")

        # Both should be positive
        assert aa > 0
        assert ra > 0


# =============================================================================
# COSINE SIMILARITY TESTS
# =============================================================================

class TestCosineSimilarity:
    """Tests for attribute-based cosine similarity."""

    def test_cosine_similar_attributes(self, attribute_graph):
        """Test cosine similarity with similar attributes."""
        nodes, edges = attribute_graph
        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        # N1 and N2 have very similar attributes
        score = engine.cosine_similarity("N1", "N2")

        # Should be high (similar risk, confidence, tags)
        assert score > 0.8

    def test_cosine_different_attributes(self, attribute_graph):
        """Test cosine similarity with different attributes."""
        nodes, edges = attribute_graph
        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        # N1 (malicious) vs N3 (legitimate)
        score = engine.cosine_similarity("N1", "N3")

        # Should be lower than N1-N2
        similar_score = engine.cosine_similarity("N1", "N2")
        assert score < similar_score

    def test_find_similar_cosine(self, attribute_graph):
        """Test finding similar with cosine."""
        nodes, edges = attribute_graph
        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        result = engine.find_similar_cosine("N1", top_k=5)

        assert result.method == "cosine"
        # N2 should be most similar
        assert result.similar_entities[0].entity_b == "N2"


# =============================================================================
# SIMRANK TESTS
# =============================================================================

class TestSimRank:
    """Tests for SimRank structural similarity."""

    def test_simrank_self_similarity(self, simple_graph):
        """Test that SimRank(a,a) = 1."""
        nodes, edges = simple_graph
        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        sim = engine.simrank(max_iterations=5)

        # Self-similarity should be 1
        assert sim.get(("A1", "A1"), 0) == 1.0

    def test_simrank_symmetric(self, simple_graph):
        """Test that SimRank is symmetric."""
        nodes, edges = simple_graph
        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        sim = engine.simrank(max_iterations=5)

        # sim(a,b) should equal sim(b,a)
        key_ab = ("A1", "A2") if "A1" <= "A2" else ("A2", "A1")
        key_ba = ("A2", "A1") if "A2" <= "A1" else ("A1", "A2")

        # Both should map to same key
        assert key_ab == key_ba

    def test_find_similar_simrank(self, simple_graph):
        """Test finding similar with SimRank."""
        nodes, edges = simple_graph
        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        result = engine.find_similar_simrank("A1", top_k=5)

        assert result.method == "simrank"


# =============================================================================
# BULK SIMILARITY TESTS
# =============================================================================

class TestBulkSimilarity:
    """Tests for bulk similarity computation."""

    def test_compute_all_pairs_jaccard(self, simple_graph):
        """Test computing all pairs with Jaccard."""
        nodes, edges = simple_graph
        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        result = engine.compute_all_pairs(method="jaccard", min_score=0.1)

        assert isinstance(result, BulkSimilarityResult)
        assert result.method == "jaccard"
        assert result.pair_count > 0

        # A1-A2 should be in results with high score
        a1_a2_pair = None
        for pair in result.pairs:
            if {pair.entity_a, pair.entity_b} == {"A1", "A2"}:
                a1_a2_pair = pair
                break

        assert a1_a2_pair is not None
        assert a1_a2_pair.score == 1.0

    def test_compute_all_pairs_same_type(self, simple_graph):
        """Test bulk computation with same-type constraint."""
        nodes, edges = simple_graph
        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        result = engine.compute_all_pairs(
            method="jaccard",
            min_score=0.0,
            same_type_only=True
        )

        # Should only have IP-IP and Domain-Domain pairs
        for pair in result.pairs:
            node_a = engine._nodes[pair.entity_a]
            node_b = engine._nodes[pair.entity_b]
            assert node_a.entity_type == node_b.entity_type


# =============================================================================
# TYPE-SPECIFIC SIMILARITY TESTS
# =============================================================================

class TestTypeSpecificSimilarity:
    """Tests for type-specific similarity functions."""

    def test_find_similar_infrastructure(self, threat_graph):
        """Test infrastructure similarity."""
        nodes, edges = threat_graph
        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        result = engine.find_similar_infrastructure("IP1", top_k=5)

        assert result.method == "infrastructure"
        # IP2 should be similar (colocated, hosts similar domain)
        if result.similar_entities:
            top_match = result.similar_entities[0]
            assert top_match.entity_b in ["IP2", "DOM1"]

    def test_find_similar_threat_actors(self, threat_graph):
        """Test threat actor similarity."""
        nodes, edges = threat_graph
        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        result = engine.find_similar_threat_actors("TA1", top_k=5)

        assert result.method == "threat_actor"
        # TA2 should be most similar (shares malware)
        if result.similar_entities:
            top_match = result.similar_entities[0]
            assert top_match.entity_b == "TA2"


# =============================================================================
# CONVENIENCE FUNCTION TESTS
# =============================================================================

class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_find_similar_entities(self, simple_graph):
        """Test find_similar_entities function."""
        nodes, edges = simple_graph

        result = find_similar_entities(nodes, edges, "A1", method="jaccard", top_k=5)

        assert isinstance(result, SimilarityResult)
        assert result.query_entity == "A1"

    def test_compute_pairwise_similarity(self, simple_graph):
        """Test compute_pairwise_similarity function."""
        nodes, edges = simple_graph

        result = compute_pairwise_similarity(nodes, edges, method="jaccard", min_score=0.1)

        assert isinstance(result, BulkSimilarityResult)
        assert result.pair_count > 0


# =============================================================================
# RESULT SERIALIZATION TESTS
# =============================================================================

class TestResultSerialization:
    """Tests for result to_dict methods."""

    def test_similarity_score_to_dict(self):
        """Test SimilarityScore serialization."""
        score = SimilarityScore(
            entity_a="A",
            entity_b="B",
            score=0.75,
            method="jaccard",
            common_neighbors=["C", "D"],
            explanation="Test"
        )

        result_dict = score.to_dict()

        assert result_dict["entity_a"] == "A"
        assert result_dict["entity_b"] == "B"
        assert result_dict["score"] == 0.75
        assert result_dict["method"] == "jaccard"

    def test_similarity_result_to_dict(self, simple_graph):
        """Test SimilarityResult serialization."""
        nodes, edges = simple_graph
        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        result = engine.find_similar_jaccard("A1", top_k=5)
        result_dict = result.to_dict()

        assert "method" in result_dict
        assert "query_entity" in result_dict
        assert "result_count" in result_dict
        assert "similar_entities" in result_dict

    def test_bulk_result_to_dict(self, simple_graph):
        """Test BulkSimilarityResult serialization."""
        nodes, edges = simple_graph
        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        result = engine.compute_all_pairs(method="jaccard", min_score=0.1)
        result_dict = result.to_dict()

        assert "method" in result_dict
        assert "pair_count" in result_dict
        assert "top_pairs" in result_dict


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_graph(self):
        """Test similarity on empty graph."""
        engine = SimilarityEngine()
        engine.build_graph([], [])

        result = engine.find_similar_jaccard("nonexistent", top_k=5)

        assert result.similar_entities == []

    def test_isolated_node(self):
        """Test similarity with isolated node."""
        nodes = [
            GraphNode(entity_id="A", entity_type=ExtendedEntityType.IP_ADDRESS, value="1.1.1.1"),
            GraphNode(entity_id="B", entity_type=ExtendedEntityType.IP_ADDRESS, value="2.2.2.2"),
        ]
        edges = []

        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        score = engine.jaccard_similarity("A", "B")
        assert score == 0.0

    def test_single_neighbor(self):
        """Test with single shared neighbor."""
        nodes = [
            GraphNode(entity_id="A", entity_type=ExtendedEntityType.IP_ADDRESS, value="1.1.1.1"),
            GraphNode(entity_id="B", entity_type=ExtendedEntityType.IP_ADDRESS, value="2.2.2.2"),
            GraphNode(entity_id="C", entity_type=ExtendedEntityType.DOMAIN, value="shared.com"),
        ]
        edges = [
            GraphEdge(source_id="A", target_id="C", relationship_type=ExtendedRelationshipType.RESOLVES_TO, weight=1.0),
            GraphEdge(source_id="B", target_id="C", relationship_type=ExtendedRelationshipType.RESOLVES_TO, weight=1.0),
        ]

        engine = SimilarityEngine()
        engine.build_graph(nodes, edges)

        score = engine.jaccard_similarity("A", "B")
        # Both have only C as neighbor, Jaccard = 1/1 = 1.0
        assert score == 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
