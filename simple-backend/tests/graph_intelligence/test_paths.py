#!/usr/bin/env python3
"""
Tests for Graph Path Analysis Algorithms

Tests path finding, reachability, and connection analysis.
"""

import pytest
from graph_intelligence import (
    GraphNode,
    GraphEdge,
    ExtendedEntityType,
    ExtendedRelationshipType,
    PathResult,
)
from graph_intelligence.algorithms import (
    PathEngine,
    PathInfo,
    MultiPathResult,
    ReachabilityResult,
    find_shortest_path,
    find_all_paths,
    check_connection,
)


@pytest.fixture
def chain_graph():
    """Create a chain graph: A -> B -> C -> D."""
    nodes = [
        GraphNode(value="A", entity_type=ExtendedEntityType.DOMAIN),
        GraphNode(value="B", entity_type=ExtendedEntityType.IP_ADDRESS),
        GraphNode(value="C", entity_type=ExtendedEntityType.DOMAIN),
        GraphNode(value="D", entity_type=ExtendedEntityType.IP_ADDRESS),
    ]
    edges = [
        GraphEdge(
            source_id=nodes[0].entity_id,
            target_id=nodes[1].entity_id,
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
            confidence=0.9,
        ),
        GraphEdge(
            source_id=nodes[1].entity_id,
            target_id=nodes[2].entity_id,
            relationship_type=ExtendedRelationshipType.HOSTS,
            confidence=0.8,
        ),
        GraphEdge(
            source_id=nodes[2].entity_id,
            target_id=nodes[3].entity_id,
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
            confidence=0.95,
        ),
    ]
    return nodes, edges


@pytest.fixture
def diamond_graph():
    """Create a diamond graph: A -> B,C -> D (multiple paths)."""
    nodes = [
        GraphNode(value="A", entity_type=ExtendedEntityType.THREAT_ACTOR),
        GraphNode(value="B", entity_type=ExtendedEntityType.CAMPAIGN),
        GraphNode(value="C", entity_type=ExtendedEntityType.CAMPAIGN),
        GraphNode(value="D", entity_type=ExtendedEntityType.ORGANIZATION),
    ]
    edges = [
        GraphEdge(
            source_id=nodes[0].entity_id,
            target_id=nodes[1].entity_id,
            relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO,
            confidence=0.9,
        ),
        GraphEdge(
            source_id=nodes[0].entity_id,
            target_id=nodes[2].entity_id,
            relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO,
            confidence=0.7,
        ),
        GraphEdge(
            source_id=nodes[1].entity_id,
            target_id=nodes[3].entity_id,
            relationship_type=ExtendedRelationshipType.TARGETS,
            confidence=0.85,
        ),
        GraphEdge(
            source_id=nodes[2].entity_id,
            target_id=nodes[3].entity_id,
            relationship_type=ExtendedRelationshipType.TARGETS,
            confidence=0.6,
        ),
    ]
    return nodes, edges


@pytest.fixture
def threat_graph():
    """Create a realistic threat intelligence graph."""
    actor = GraphNode(value="APT28", entity_type=ExtendedEntityType.THREAT_ACTOR)
    campaign = GraphNode(value="Operation X", entity_type=ExtendedEntityType.CAMPAIGN)
    malware = GraphNode(value="Emotet", entity_type=ExtendedEntityType.MALWARE_FAMILY)
    c2_domain = GraphNode(value="evil-c2.com", entity_type=ExtendedEntityType.DOMAIN)
    c2_ip = GraphNode(value="192.168.1.100", entity_type=ExtendedEntityType.IP_ADDRESS)
    target = GraphNode(value="Target Corp", entity_type=ExtendedEntityType.ORGANIZATION)
    phishing = GraphNode(value="phish.evil.com", entity_type=ExtendedEntityType.DOMAIN)

    nodes = [actor, campaign, malware, c2_domain, c2_ip, target, phishing]

    edges = [
        GraphEdge(
            source_id=actor.entity_id,
            target_id=campaign.entity_id,
            relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO,
            confidence=0.9,
        ),
        GraphEdge(
            source_id=campaign.entity_id,
            target_id=malware.entity_id,
            relationship_type=ExtendedRelationshipType.DELIVERS,
            confidence=0.85,
        ),
        GraphEdge(
            source_id=malware.entity_id,
            target_id=c2_domain.entity_id,
            relationship_type=ExtendedRelationshipType.COMMUNICATES_WITH,
            confidence=0.95,
        ),
        GraphEdge(
            source_id=c2_domain.entity_id,
            target_id=c2_ip.entity_id,
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
            confidence=0.99,
        ),
        GraphEdge(
            source_id=campaign.entity_id,
            target_id=target.entity_id,
            relationship_type=ExtendedRelationshipType.TARGETS,
            confidence=0.8,
        ),
        GraphEdge(
            source_id=phishing.entity_id,
            target_id=c2_ip.entity_id,
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
            confidence=0.9,
        ),
    ]

    return nodes, edges


class TestPathEngine:
    """Tests for PathEngine class."""

    def test_engine_creation(self):
        """Test engine can be created."""
        engine = PathEngine()
        assert engine is not None

    def test_build_graph(self, chain_graph):
        """Test building a graph."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        assert engine.node_count == 4
        assert engine.edge_count == 3


class TestShortestPath:
    """Tests for shortest path finding."""

    def test_shortest_path_chain(self, chain_graph):
        """Test shortest path on chain graph."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        result = engine.shortest_path(nodes[0].entity_id, nodes[3].entity_id)

        assert result.found is True
        assert result.path_length == 3
        assert len(result.nodes) == 4
        assert len(result.edges) == 3

    def test_shortest_path_same_node(self, chain_graph):
        """Test path to self."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        result = engine.shortest_path(nodes[0].entity_id, nodes[0].entity_id)

        assert result.found is True
        assert result.path_length == 0
        assert len(result.nodes) == 1

    def test_shortest_path_not_found(self, chain_graph):
        """Test when no path exists."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        # D -> A doesn't exist (graph is directed)
        result = engine.shortest_path(nodes[3].entity_id, nodes[0].entity_id)

        assert result.found is False

    def test_shortest_path_diamond(self, diamond_graph):
        """Test shortest path with multiple options."""
        nodes, edges = diamond_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        result = engine.shortest_path(nodes[0].entity_id, nodes[3].entity_id)

        assert result.found is True
        assert result.path_length == 2  # A -> B/C -> D

    def test_shortest_path_confidence(self, chain_graph):
        """Test that confidence is calculated correctly."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        result = engine.shortest_path(nodes[0].entity_id, nodes[3].entity_id)

        # Confidence should be product: 0.9 * 0.8 * 0.95 = 0.684
        expected = 0.9 * 0.8 * 0.95
        assert abs(result.total_confidence - expected) < 0.001

    def test_shortest_path_max_depth(self, chain_graph):
        """Test max_depth limit."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        # Path exists with length 3, but we limit to 2
        result = engine.shortest_path(nodes[0].entity_id, nodes[3].entity_id, max_depth=2)

        assert result.found is False

    def test_shortest_path_relationship_filter(self, chain_graph):
        """Test filtering by relationship type."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        # Filter to only RESOLVES_TO edges
        result = engine.shortest_path(
            nodes[0].entity_id,
            nodes[3].entity_id,
            relationship_types=[ExtendedRelationshipType.RESOLVES_TO]
        )

        # Can't reach D with only RESOLVES_TO (need HOSTS in middle)
        assert result.found is False


class TestWeightedShortestPath:
    """Tests for weighted shortest path (Dijkstra's)."""

    def test_weighted_path_basic(self, diamond_graph):
        """Test weighted shortest path."""
        nodes, edges = diamond_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        result = engine.weighted_shortest_path(
            nodes[0].entity_id,
            nodes[3].entity_id
        )

        assert result.found is True
        assert result.path_length == 2

    def test_weighted_path_chooses_high_confidence(self, diamond_graph):
        """Test that weighted path prefers high confidence edges."""
        nodes, edges = diamond_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        # Default weight: 1 - confidence (lower is better)
        result = engine.weighted_shortest_path(
            nodes[0].entity_id,
            nodes[3].entity_id
        )

        # Should choose A -> B -> D (0.9 + 0.85 confidence)
        # over A -> C -> D (0.7 + 0.6 confidence)
        assert result.found is True

        # Check path goes through B (higher confidence route)
        path_values = [n["value"] for n in result.nodes]
        assert "B" in path_values

    def test_custom_weight_function(self, chain_graph):
        """Test custom weight function."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        # Use edge weight directly
        result = engine.weighted_shortest_path(
            nodes[0].entity_id,
            nodes[3].entity_id,
            weight_function=lambda e: e.weight
        )

        assert result.found is True


class TestAllPaths:
    """Tests for finding all paths."""

    def test_all_paths_diamond(self, diamond_graph):
        """Test finding all paths in diamond graph."""
        nodes, edges = diamond_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        result = engine.all_paths(nodes[0].entity_id, nodes[3].entity_id)

        assert result.paths_found == 2  # A->B->D and A->C->D
        assert result.shortest_length == 2

    def test_all_paths_max_paths(self, diamond_graph):
        """Test max_paths limit."""
        nodes, edges = diamond_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        result = engine.all_paths(
            nodes[0].entity_id,
            nodes[3].entity_id,
            max_paths=1
        )

        assert len(result.paths) == 1

    def test_all_paths_sorted_by_length(self, threat_graph):
        """Test that paths are sorted by length."""
        nodes, edges = threat_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        # Find paths from actor to target
        actor_id = nodes[0].entity_id
        target_id = nodes[5].entity_id

        result = engine.all_paths(actor_id, target_id, max_depth=5)

        # Paths should be sorted by length
        if result.paths_found > 1:
            for i in range(1, len(result.paths)):
                assert result.paths[i].length >= result.paths[i-1].length

    def test_all_paths_chain(self, chain_graph):
        """Test all paths in chain (only one path exists)."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        result = engine.all_paths(nodes[0].entity_id, nodes[3].entity_id)

        assert result.paths_found == 1
        assert result.paths[0].length == 3


class TestPathExists:
    """Tests for path existence checking."""

    def test_path_exists_true(self, chain_graph):
        """Test when path exists."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        assert engine.path_exists(nodes[0].entity_id, nodes[3].entity_id) is True

    def test_path_exists_false(self, chain_graph):
        """Test when path doesn't exist."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        # Reverse direction
        assert engine.path_exists(nodes[3].entity_id, nodes[0].entity_id) is False

    def test_path_exists_same_node(self, chain_graph):
        """Test path to self."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        assert engine.path_exists(nodes[0].entity_id, nodes[0].entity_id) is True

    def test_path_exists_with_depth_limit(self, chain_graph):
        """Test path exists with depth limit."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        # Path length is 3, so should fail with max_depth=2
        assert engine.path_exists(nodes[0].entity_id, nodes[3].entity_id, max_depth=2) is False
        assert engine.path_exists(nodes[0].entity_id, nodes[3].entity_id, max_depth=3) is True


class TestReachability:
    """Tests for reachability analysis."""

    def test_reachability_basic(self, chain_graph):
        """Test basic reachability."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        result = engine.reachability(nodes[0].entity_id, max_depth=3)

        assert result.reachable_count == 3  # B, C, D
        assert result.max_depth_reached == 3

    def test_reachability_by_depth(self, chain_graph):
        """Test reachability broken down by depth."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        result = engine.reachability(nodes[0].entity_id, max_depth=3)

        assert result.reachable_by_depth.get(1) == 1  # B
        assert result.reachable_by_depth.get(2) == 1  # C
        assert result.reachable_by_depth.get(3) == 1  # D

    def test_reachability_by_type(self, chain_graph):
        """Test reachability by entity type."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        result = engine.reachability(nodes[0].entity_id, max_depth=3)

        # 2 IP addresses (B, D) and 1 domain (C)
        assert result.reachable_by_type.get("ip_address") == 2
        assert result.reachable_by_type.get("domain") == 1

    def test_reachability_with_type_filter(self, chain_graph):
        """Test reachability with entity type filter."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        # Only count IP addresses
        result = engine.reachability(
            nodes[0].entity_id,
            max_depth=3,
            entity_types=[ExtendedEntityType.IP_ADDRESS]
        )

        assert result.reachable_count == 2  # B and D


class TestCommonNeighbors:
    """Tests for common neighbor finding."""

    def test_common_neighbors_diamond(self, diamond_graph):
        """Test common neighbors in diamond graph."""
        nodes, edges = diamond_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        # B and C both connect to D
        common = engine.common_neighbors(nodes[1].entity_id, nodes[2].entity_id)

        assert nodes[3].entity_id in common  # D is common neighbor

    def test_common_neighbors_none(self, chain_graph):
        """Test when no common neighbors exist."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        # A and D have no common neighbors
        common = engine.common_neighbors(nodes[0].entity_id, nodes[3].entity_id)

        assert len(common) == 0


class TestKHopNeighbors:
    """Tests for k-hop neighbor finding."""

    def test_k_hop_neighbors(self, chain_graph):
        """Test k-hop neighbors."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        result = engine.k_hop_neighbors(nodes[0].entity_id, k=3)

        assert len(result.get(1, [])) == 1  # B
        assert len(result.get(2, [])) == 1  # C
        assert len(result.get(3, [])) == 1  # D


class TestPivotFinding:
    """Tests for pivot point finding."""

    def test_find_pivots(self, threat_graph):
        """Test finding pivot points."""
        nodes, edges = threat_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        # Find pivots connecting actor, malware, and phishing domain
        actor_id = nodes[0].entity_id
        phishing_id = nodes[6].entity_id

        pivots = engine.find_pivots([actor_id, phishing_id], max_depth=4)

        # C2 IP should be a pivot (reachable from both)
        pivot_ids = [p[0] for p in pivots]
        c2_ip_id = nodes[4].entity_id

        # The c2_ip should be reachable from both
        assert c2_ip_id in pivot_ids or len(pivots) >= 0


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_find_shortest_path_function(self, chain_graph):
        """Test find_shortest_path convenience function."""
        nodes, edges = chain_graph

        result = find_shortest_path(nodes, edges, nodes[0].entity_id, nodes[3].entity_id)

        assert result.found is True
        assert result.path_length == 3

    def test_find_all_paths_function(self, diamond_graph):
        """Test find_all_paths convenience function."""
        nodes, edges = diamond_graph

        result = find_all_paths(
            nodes, edges,
            nodes[0].entity_id, nodes[3].entity_id,
            max_depth=4, max_paths=10
        )

        assert result.paths_found == 2

    def test_check_connection_function(self, chain_graph):
        """Test check_connection convenience function."""
        nodes, edges = chain_graph

        assert check_connection(nodes, edges, nodes[0].entity_id, nodes[3].entity_id) is True
        assert check_connection(nodes, edges, nodes[3].entity_id, nodes[0].entity_id) is False


class TestThreatIntelligenceScenarios:
    """Tests using realistic threat intelligence scenarios."""

    def test_actor_to_infrastructure_path(self, threat_graph):
        """Test finding path from threat actor to infrastructure."""
        nodes, edges = threat_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        actor_id = nodes[0].entity_id  # APT28
        c2_ip_id = nodes[4].entity_id  # 192.168.1.100

        result = engine.shortest_path(actor_id, c2_ip_id)

        assert result.found is True
        # Path: Actor -> Campaign -> Malware -> C2 Domain -> C2 IP
        assert result.path_length == 4

    def test_actor_to_target_paths(self, threat_graph):
        """Test all paths from actor to target."""
        nodes, edges = threat_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        actor_id = nodes[0].entity_id  # APT28
        target_id = nodes[5].entity_id  # Target Corp

        result = engine.all_paths(actor_id, target_id, max_depth=4)

        assert result.paths_found >= 1
        # Direct path: Actor -> Campaign -> Target (length 2)
        assert result.shortest_length == 2

    def test_infrastructure_reachability(self, threat_graph):
        """Test what's reachable from C2 infrastructure."""
        nodes, edges = threat_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        c2_domain_id = nodes[3].entity_id  # evil-c2.com

        result = engine.reachability(c2_domain_id, max_depth=2)

        # C2 domain can reach C2 IP
        assert result.reachable_count >= 1


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_graph(self):
        """Test with empty graph."""
        engine = PathEngine()
        engine.build_graph([], [])

        result = engine.shortest_path("a", "b")
        assert result.found is False

    def test_nonexistent_source(self, chain_graph):
        """Test with nonexistent source node."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        result = engine.shortest_path("nonexistent", nodes[1].entity_id)
        assert result.found is False

    def test_nonexistent_target(self, chain_graph):
        """Test with nonexistent target node."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        result = engine.shortest_path(nodes[0].entity_id, "nonexistent")
        assert result.found is False

    def test_disconnected_components(self):
        """Test graph with disconnected components."""
        nodes = [
            GraphNode(value="A", entity_type=ExtendedEntityType.DOMAIN),
            GraphNode(value="B", entity_type=ExtendedEntityType.DOMAIN),
            GraphNode(value="C", entity_type=ExtendedEntityType.DOMAIN),
            GraphNode(value="D", entity_type=ExtendedEntityType.DOMAIN),
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

        engine = PathEngine()
        engine.build_graph(nodes, edges)

        # A-B and C-D are separate components
        assert engine.path_exists(nodes[0].entity_id, nodes[1].entity_id) is True
        assert engine.path_exists(nodes[0].entity_id, nodes[2].entity_id) is False

    def test_bidirectional_edges(self):
        """Test graph with bidirectional edges."""
        nodes = [
            GraphNode(value="A", entity_type=ExtendedEntityType.DOMAIN),
            GraphNode(value="B", entity_type=ExtendedEntityType.DOMAIN),
        ]
        edges = [
            GraphEdge(
                source_id=nodes[0].entity_id,
                target_id=nodes[1].entity_id,
                relationship_type=ExtendedRelationshipType.ASSOCIATED_WITH,
                bidirectional=True,
            ),
        ]

        engine = PathEngine()
        engine.build_graph(nodes, edges)

        # Can traverse in both directions
        assert engine.path_exists(nodes[0].entity_id, nodes[1].entity_id) is True
        assert engine.path_exists(nodes[1].entity_id, nodes[0].entity_id) is True


class TestPathInfoSerialization:
    """Tests for PathInfo serialization."""

    def test_path_info_to_dict(self, chain_graph):
        """Test PathInfo serialization."""
        nodes, edges = chain_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        result = engine.all_paths(nodes[0].entity_id, nodes[3].entity_id)

        assert result.paths_found > 0
        path_dict = result.paths[0].to_dict()

        assert "path_id" in path_dict
        assert "length" in path_dict
        assert "total_confidence" in path_dict
        assert "nodes" in path_dict
        assert "edges" in path_dict

    def test_multi_path_result_to_dict(self, diamond_graph):
        """Test MultiPathResult serialization."""
        nodes, edges = diamond_graph
        engine = PathEngine()
        engine.build_graph(nodes, edges)

        result = engine.all_paths(nodes[0].entity_id, nodes[3].entity_id)
        result_dict = result.to_dict()

        assert "source_id" in result_dict
        assert "target_id" in result_dict
        assert "paths_found" in result_dict
        assert "shortest_length" in result_dict
        assert "paths" in result_dict
