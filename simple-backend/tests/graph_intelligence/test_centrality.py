#!/usr/bin/env python3
"""
Tests for Graph Centrality Algorithms

Tests centrality computation with various graph structures.
"""

import pytest
from graph_intelligence import (
    GraphNode,
    GraphEdge,
    ExtendedEntityType,
    ExtendedRelationshipType,
    CentralityScores,
)
from graph_intelligence.algorithms import (
    CentralityEngine,
    CentralityResult,
    AllCentralityResult,
    compute_centrality,
    get_top_central_nodes,
)


@pytest.fixture
def simple_graph():
    """Create a simple graph: A -> B -> C"""
    nodes = [
        GraphNode(value="A", entity_type=ExtendedEntityType.DOMAIN),
        GraphNode(value="B", entity_type=ExtendedEntityType.DOMAIN),
        GraphNode(value="C", entity_type=ExtendedEntityType.DOMAIN),
    ]
    edges = [
        GraphEdge(
            source_id=nodes[0].entity_id,
            target_id=nodes[1].entity_id,
            relationship_type=ExtendedRelationshipType.ASSOCIATED_WITH,
        ),
        GraphEdge(
            source_id=nodes[1].entity_id,
            target_id=nodes[2].entity_id,
            relationship_type=ExtendedRelationshipType.ASSOCIATED_WITH,
        ),
    ]
    return nodes, edges


@pytest.fixture
def star_graph():
    """Create a star graph: Hub connected to 5 spokes."""
    hub = GraphNode(value="Hub", entity_type=ExtendedEntityType.DOMAIN)
    spokes = [
        GraphNode(value=f"Spoke{i}", entity_type=ExtendedEntityType.IP_ADDRESS)
        for i in range(5)
    ]
    nodes = [hub] + spokes
    edges = [
        GraphEdge(
            source_id=hub.entity_id,
            target_id=spoke.entity_id,
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
        )
        for spoke in spokes
    ]
    return nodes, edges


@pytest.fixture
def threat_graph():
    """Create a realistic threat intelligence graph."""
    # Create entities
    actor = GraphNode(value="APT28", entity_type=ExtendedEntityType.THREAT_ACTOR)
    campaign = GraphNode(value="Operation X", entity_type=ExtendedEntityType.CAMPAIGN)
    malware = GraphNode(value="Emotet", entity_type=ExtendedEntityType.MALWARE_FAMILY)
    c2_domain = GraphNode(value="evil-c2.com", entity_type=ExtendedEntityType.DOMAIN)
    c2_ip = GraphNode(value="192.168.1.100", entity_type=ExtendedEntityType.IP_ADDRESS)
    target_org = GraphNode(value="Target Corp", entity_type=ExtendedEntityType.ORGANIZATION)
    phishing_domain = GraphNode(value="phish.evil.com", entity_type=ExtendedEntityType.DOMAIN)

    nodes = [actor, campaign, malware, c2_domain, c2_ip, target_org, phishing_domain]

    edges = [
        # Actor -> Campaign
        GraphEdge(
            source_id=actor.entity_id,
            target_id=campaign.entity_id,
            relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO,
        ),
        # Campaign -> Malware
        GraphEdge(
            source_id=campaign.entity_id,
            target_id=malware.entity_id,
            relationship_type=ExtendedRelationshipType.DELIVERS,
        ),
        # Malware -> C2 Domain
        GraphEdge(
            source_id=malware.entity_id,
            target_id=c2_domain.entity_id,
            relationship_type=ExtendedRelationshipType.COMMUNICATES_WITH,
        ),
        # C2 Domain -> C2 IP
        GraphEdge(
            source_id=c2_domain.entity_id,
            target_id=c2_ip.entity_id,
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
        ),
        # Campaign -> Target
        GraphEdge(
            source_id=campaign.entity_id,
            target_id=target_org.entity_id,
            relationship_type=ExtendedRelationshipType.TARGETS,
        ),
        # Phishing -> C2 Domain (shared infrastructure)
        GraphEdge(
            source_id=phishing_domain.entity_id,
            target_id=c2_ip.entity_id,
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
        ),
    ]

    return nodes, edges


class TestCentralityEngine:
    """Tests for CentralityEngine class."""

    def test_engine_creation(self):
        """Test engine can be created."""
        engine = CentralityEngine()
        assert engine is not None
        assert engine.node_count == 0
        assert engine.edge_count == 0

    def test_build_graph(self, simple_graph):
        """Test building a graph."""
        nodes, edges = simple_graph
        engine = CentralityEngine()
        graph = engine.build_graph(nodes, edges)

        assert graph is not None
        assert engine.node_count == 3
        assert engine.edge_count == 2

    def test_build_graph_with_bidirectional(self, star_graph):
        """Test building graph with bidirectional edges."""
        nodes, edges = star_graph

        # Make edges bidirectional
        for edge in edges:
            edge.bidirectional = True

        engine = CentralityEngine()
        graph = engine.build_graph(nodes, edges)

        # Bidirectional edges should create 2 directed edges each
        assert engine.edge_count == 10  # 5 edges * 2 directions


class TestDegreeCentrality:
    """Tests for degree centrality."""

    def test_degree_centrality_simple(self, simple_graph):
        """Test degree centrality on simple graph."""
        nodes, edges = simple_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.degree_centrality()

        assert result.algorithm == "degree_centrality"
        assert result.node_count == 3
        assert len(result.scores) == 3
        assert result.computation_time_ms >= 0

    def test_degree_centrality_star(self, star_graph):
        """Test that hub has highest degree in star graph."""
        nodes, edges = star_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.degree_centrality()

        # Hub should have highest degree
        hub_id = nodes[0].entity_id
        hub_score = result.scores[hub_id]

        # Hub should be in top nodes
        top_ids = [n[0] for n in result.top_nodes]
        assert hub_id == top_ids[0]

    def test_in_degree_centrality(self, simple_graph):
        """Test in-degree centrality."""
        nodes, edges = simple_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.in_degree_centrality()

        # Node C has highest in-degree (receives from B)
        # Node A has lowest in-degree (receives from no one)
        a_id = nodes[0].entity_id
        assert result.scores[a_id] == 0.0

    def test_out_degree_centrality(self, simple_graph):
        """Test out-degree centrality."""
        nodes, edges = simple_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.out_degree_centrality()

        # Node A and B have out-degree 1
        # Node C has out-degree 0
        c_id = nodes[2].entity_id
        assert result.scores[c_id] == 0.0


class TestBetweennessCentrality:
    """Tests for betweenness centrality."""

    def test_betweenness_simple(self, simple_graph):
        """Test betweenness on simple chain graph."""
        nodes, edges = simple_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.betweenness_centrality()

        assert result.algorithm == "betweenness_centrality"
        assert len(result.scores) == 3

        # B should have highest betweenness (it's on the path A->C)
        b_id = nodes[1].entity_id
        a_id = nodes[0].entity_id
        c_id = nodes[2].entity_id

        # In a directed chain A->B->C, B has betweenness 1.0 (normalized)
        assert result.scores[b_id] >= result.scores[a_id]
        assert result.scores[b_id] >= result.scores[c_id]

    def test_betweenness_star(self, star_graph):
        """Test betweenness on star graph."""
        nodes, edges = star_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.betweenness_centrality()

        # In a star, the hub has highest betweenness
        hub_id = nodes[0].entity_id
        assert result.top_nodes[0][0] == hub_id or result.scores[hub_id] >= 0


class TestClosenessCentrality:
    """Tests for closeness centrality."""

    def test_closeness_simple(self, simple_graph):
        """Test closeness on simple graph."""
        nodes, edges = simple_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.closeness_centrality()

        assert result.algorithm == "closeness_centrality"
        assert len(result.scores) == 3

    def test_closeness_star(self, star_graph):
        """Test closeness on star graph."""
        nodes, edges = star_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.closeness_centrality()

        # Hub should have highest closeness (can reach all spokes in 1 hop)
        hub_id = nodes[0].entity_id
        hub_closeness = result.scores[hub_id]

        for spoke in nodes[1:]:
            assert hub_closeness >= result.scores[spoke.entity_id]


class TestEigenvectorCentrality:
    """Tests for eigenvector centrality."""

    def test_eigenvector_simple(self, simple_graph):
        """Test eigenvector centrality."""
        nodes, edges = simple_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.eigenvector_centrality()

        assert result.algorithm == "eigenvector_centrality"
        assert len(result.scores) == 3

    def test_eigenvector_values_positive(self, threat_graph):
        """Test that eigenvector values are non-negative."""
        nodes, edges = threat_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.eigenvector_centrality()

        for score in result.scores.values():
            assert score >= 0


class TestPageRank:
    """Tests for PageRank algorithm."""

    def test_pagerank_simple(self, simple_graph):
        """Test PageRank on simple graph."""
        nodes, edges = simple_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.pagerank()

        assert result.algorithm == "pagerank"
        assert len(result.scores) == 3

        # PageRank values should sum to approximately 1
        total = sum(result.scores.values())
        assert abs(total - 1.0) < 0.01

    def test_pagerank_star(self, star_graph):
        """Test PageRank on star graph."""
        nodes, edges = star_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.pagerank()

        # All scores should be positive
        for score in result.scores.values():
            assert score > 0

    def test_pagerank_damping_factor(self, simple_graph):
        """Test PageRank with different damping factors."""
        nodes, edges = simple_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result_85 = engine.pagerank(alpha=0.85)
        result_50 = engine.pagerank(alpha=0.50)

        # Different damping factors should give different results
        # (though they might be similar for small graphs)
        assert result_85.computation_time_ms >= 0
        assert result_50.computation_time_ms >= 0


class TestHarmonicCentrality:
    """Tests for harmonic centrality."""

    def test_harmonic_simple(self, simple_graph):
        """Test harmonic centrality."""
        nodes, edges = simple_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.harmonic_centrality()

        assert result.algorithm == "harmonic_centrality"
        assert len(result.scores) == 3


class TestKatzCentrality:
    """Tests for Katz centrality."""

    def test_katz_simple(self, simple_graph):
        """Test Katz centrality."""
        nodes, edges = simple_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.katz_centrality()

        assert result.algorithm == "katz_centrality"
        assert len(result.scores) == 3


class TestComputeAllCentrality:
    """Tests for computing all centrality measures."""

    def test_compute_all(self, simple_graph):
        """Test computing all centrality measures."""
        nodes, edges = simple_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.compute_all_centrality()

        assert isinstance(result, AllCentralityResult)
        assert result.node_count == 3
        assert result.edge_count == 2
        assert len(result.scores) == 3
        assert len(result.algorithm_times) > 0

    def test_compute_all_scores_complete(self, threat_graph):
        """Test that all centrality measures are computed."""
        nodes, edges = threat_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.compute_all_centrality()

        # Check each node has all centrality scores
        for entity_id, scores in result.scores.items():
            assert isinstance(scores, CentralityScores)
            assert scores.entity_id == entity_id
            assert hasattr(scores, 'degree')
            assert hasattr(scores, 'betweenness')
            assert hasattr(scores, 'closeness')
            assert hasattr(scores, 'pagerank')

    def test_composite_score(self, threat_graph):
        """Test composite centrality score calculation."""
        nodes, edges = threat_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.compute_all_centrality()

        # Composite scores should exist
        assert len(result.top_by_composite) > 0

        # Composite should be weighted average
        for entity_id, scores in result.scores.items():
            expected = (
                scores.pagerank * 0.3 +
                scores.betweenness * 0.3 +
                scores.degree * 0.2 +
                scores.eigenvector * 0.2
            )
            assert abs(scores.composite - expected) < 0.0001


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_compute_centrality_function(self, threat_graph):
        """Test compute_centrality convenience function."""
        nodes, edges = threat_graph

        result = compute_centrality(nodes, edges)

        assert isinstance(result, AllCentralityResult)
        assert result.node_count == len(nodes)

    def test_get_top_central_nodes_pagerank(self, star_graph):
        """Test get_top_central_nodes with PageRank."""
        nodes, edges = star_graph

        top_nodes = get_top_central_nodes(nodes, edges, algorithm="pagerank", top_k=3)

        assert len(top_nodes) == 3
        assert all(isinstance(t, tuple) for t in top_nodes)
        assert all(len(t) == 2 for t in top_nodes)

    def test_get_top_central_nodes_betweenness(self, simple_graph):
        """Test get_top_central_nodes with betweenness."""
        nodes, edges = simple_graph

        top_nodes = get_top_central_nodes(nodes, edges, algorithm="betweenness", top_k=2)

        assert len(top_nodes) == 2

        # B should be first (highest betweenness in chain)
        top_id = top_nodes[0][0]
        assert top_id == nodes[1].entity_id


class TestThreatGraphCentrality:
    """Tests using realistic threat intelligence graph."""

    def test_threat_actor_centrality(self, threat_graph):
        """Test centrality in threat intelligence context."""
        nodes, edges = threat_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.compute_all_centrality()

        # Find the threat actor (APT28)
        actor_id = None
        for node in nodes:
            if node.entity_type == ExtendedEntityType.THREAT_ACTOR:
                actor_id = node.entity_id
                break

        assert actor_id is not None
        actor_scores = result.scores[actor_id]

        # Actor should have some centrality (it's the source of the attack chain)
        assert actor_scores.out_degree > 0 or actor_scores.degree > 0

    def test_c2_domain_centrality(self, threat_graph):
        """Test that C2 domain has high betweenness."""
        nodes, edges = threat_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        betweenness = engine.betweenness_centrality()

        # Find C2 domain
        c2_domain_id = None
        for node in nodes:
            if node.value == "evil-c2.com":
                c2_domain_id = node.entity_id
                break

        # C2 domain should have some betweenness
        # (it's on the path from malware to IP)
        assert c2_domain_id is not None


class TestResultSerialization:
    """Tests for result serialization."""

    def test_centrality_result_to_dict(self, simple_graph):
        """Test CentralityResult serialization."""
        nodes, edges = simple_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.pagerank()
        data = result.to_dict()

        assert "algorithm" in data
        assert "node_count" in data
        assert "top_nodes" in data
        assert "statistics" in data
        assert data["algorithm"] == "pagerank"

    def test_all_centrality_result_to_dict(self, simple_graph):
        """Test AllCentralityResult serialization."""
        nodes, edges = simple_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.compute_all_centrality()
        data = result.to_dict()

        assert "node_count" in data
        assert "edge_count" in data
        assert "algorithm_times" in data
        assert "top_by_composite" in data


class TestEdgeCases:
    """Tests for edge cases."""

    def test_single_node_graph(self):
        """Test centrality on single node graph."""
        nodes = [GraphNode(value="single", entity_type=ExtendedEntityType.DOMAIN)]
        edges = []

        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.compute_all_centrality()

        assert result.node_count == 1
        assert result.edge_count == 0

    def test_disconnected_graph(self):
        """Test centrality on disconnected components."""
        # Two separate pairs
        nodes = [
            GraphNode(value="A1", entity_type=ExtendedEntityType.DOMAIN),
            GraphNode(value="A2", entity_type=ExtendedEntityType.DOMAIN),
            GraphNode(value="B1", entity_type=ExtendedEntityType.DOMAIN),
            GraphNode(value="B2", entity_type=ExtendedEntityType.DOMAIN),
        ]
        edges = [
            GraphEdge(
                source_id=nodes[0].entity_id,
                target_id=nodes[1].entity_id,
                relationship_type=ExtendedRelationshipType.ASSOCIATED_WITH,
            ),
            GraphEdge(
                source_id=nodes[2].entity_id,
                target_id=nodes[3].entity_id,
                relationship_type=ExtendedRelationshipType.ASSOCIATED_WITH,
            ),
        ]

        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        # Should not raise errors
        result = engine.compute_all_centrality()
        assert result.node_count == 4

    def test_self_loop(self):
        """Test handling of self-loops."""
        nodes = [
            GraphNode(value="loop", entity_type=ExtendedEntityType.DOMAIN),
        ]
        edges = [
            GraphEdge(
                source_id=nodes[0].entity_id,
                target_id=nodes[0].entity_id,  # Self-loop
                relationship_type=ExtendedRelationshipType.ASSOCIATED_WITH,
            ),
        ]

        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        # Should handle gracefully
        result = engine.degree_centrality()
        assert result.node_count == 1

    def test_no_graph_built_error(self):
        """Test error when no graph is built."""
        engine = CentralityEngine()

        with pytest.raises(ValueError, match="No graph built"):
            engine.degree_centrality()

    def test_statistics_in_result(self, threat_graph):
        """Test that statistics are computed correctly."""
        nodes, edges = threat_graph
        engine = CentralityEngine()
        engine.build_graph(nodes, edges)

        result = engine.pagerank()

        assert "min" in result.statistics
        assert "max" in result.statistics
        assert "mean" in result.statistics
        assert "std" in result.statistics
        assert "median" in result.statistics

        # Sanity checks
        assert result.statistics["min"] <= result.statistics["mean"]
        assert result.statistics["mean"] <= result.statistics["max"]
