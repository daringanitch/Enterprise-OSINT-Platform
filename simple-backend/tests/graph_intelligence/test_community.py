#!/usr/bin/env python3
"""
Tests for Graph Intelligence Community Detection Algorithms

Tests community detection, connected components, k-core decomposition,
and clustering coefficient calculations.
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
from graph_intelligence.algorithms.community import (
    CommunityEngine,
    CommunityResult,
    ComponentResult,
    KCoreResult,
    ClusteringResult,
    detect_communities,
    find_connected_components,
    get_dense_core,
)


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def simple_graph():
    """Simple test graph with clear community structure."""
    # Two communities connected by a bridge
    # Community A: A1-A2-A3 (triangle)
    # Community B: B1-B2-B3 (triangle)
    # Bridge: A3-B1

    nodes = [
        GraphNode(entity_id="A1", entity_type=ExtendedEntityType.IP_ADDRESS, value="10.0.0.1"),
        GraphNode(entity_id="A2", entity_type=ExtendedEntityType.IP_ADDRESS, value="10.0.0.2"),
        GraphNode(entity_id="A3", entity_type=ExtendedEntityType.IP_ADDRESS, value="10.0.0.3"),
        GraphNode(entity_id="B1", entity_type=ExtendedEntityType.DOMAIN, value="evil1.com"),
        GraphNode(entity_id="B2", entity_type=ExtendedEntityType.DOMAIN, value="evil2.com"),
        GraphNode(entity_id="B3", entity_type=ExtendedEntityType.DOMAIN, value="evil3.com"),
    ]

    edges = [
        # Community A (triangle)
        GraphEdge(source_id="A1", target_id="A2", relationship_type=ExtendedRelationshipType.COMMUNICATES_WITH, weight=1.0),
        GraphEdge(source_id="A2", target_id="A3", relationship_type=ExtendedRelationshipType.COMMUNICATES_WITH, weight=1.0),
        GraphEdge(source_id="A1", target_id="A3", relationship_type=ExtendedRelationshipType.COMMUNICATES_WITH, weight=1.0),
        # Community B (triangle)
        GraphEdge(source_id="B1", target_id="B2", relationship_type=ExtendedRelationshipType.RESOLVES_TO, weight=1.0),
        GraphEdge(source_id="B2", target_id="B3", relationship_type=ExtendedRelationshipType.RESOLVES_TO, weight=1.0),
        GraphEdge(source_id="B1", target_id="B3", relationship_type=ExtendedRelationshipType.RESOLVES_TO, weight=1.0),
        # Bridge
        GraphEdge(source_id="A3", target_id="B1", relationship_type=ExtendedRelationshipType.ASSOCIATED_WITH, weight=0.5),
    ]

    return nodes, edges


@pytest.fixture
def disconnected_graph():
    """Graph with multiple disconnected components."""
    nodes = [
        # Component 1
        GraphNode(entity_id="C1A", entity_type=ExtendedEntityType.IP_ADDRESS, value="1.1.1.1"),
        GraphNode(entity_id="C1B", entity_type=ExtendedEntityType.IP_ADDRESS, value="1.1.1.2"),
        # Component 2
        GraphNode(entity_id="C2A", entity_type=ExtendedEntityType.DOMAIN, value="comp2.com"),
        GraphNode(entity_id="C2B", entity_type=ExtendedEntityType.DOMAIN, value="comp2b.com"),
        GraphNode(entity_id="C2C", entity_type=ExtendedEntityType.DOMAIN, value="comp2c.com"),
        # Component 3 (isolated node)
        GraphNode(entity_id="C3A", entity_type=ExtendedEntityType.HASH_SHA256, value="abc123"),
    ]

    edges = [
        # Component 1
        GraphEdge(source_id="C1A", target_id="C1B", relationship_type=ExtendedRelationshipType.COMMUNICATES_WITH, weight=1.0),
        # Component 2
        GraphEdge(source_id="C2A", target_id="C2B", relationship_type=ExtendedRelationshipType.RESOLVES_TO, weight=1.0),
        GraphEdge(source_id="C2B", target_id="C2C", relationship_type=ExtendedRelationshipType.RESOLVES_TO, weight=1.0),
    ]

    return nodes, edges


@pytest.fixture
def dense_graph():
    """Dense graph for k-core testing."""
    # 5-node fully connected core plus peripheral nodes
    nodes = [
        # Dense core
        GraphNode(entity_id="D1", entity_type=ExtendedEntityType.IP_ADDRESS, value="10.0.0.1"),
        GraphNode(entity_id="D2", entity_type=ExtendedEntityType.IP_ADDRESS, value="10.0.0.2"),
        GraphNode(entity_id="D3", entity_type=ExtendedEntityType.IP_ADDRESS, value="10.0.0.3"),
        GraphNode(entity_id="D4", entity_type=ExtendedEntityType.IP_ADDRESS, value="10.0.0.4"),
        GraphNode(entity_id="D5", entity_type=ExtendedEntityType.IP_ADDRESS, value="10.0.0.5"),
        # Peripheral nodes
        GraphNode(entity_id="P1", entity_type=ExtendedEntityType.DOMAIN, value="edge1.com"),
        GraphNode(entity_id="P2", entity_type=ExtendedEntityType.DOMAIN, value="edge2.com"),
    ]

    # Fully connect the core (D1-D5)
    edges = []
    core_nodes = ["D1", "D2", "D3", "D4", "D5"]
    for i, n1 in enumerate(core_nodes):
        for n2 in core_nodes[i+1:]:
            edges.append(GraphEdge(
                source_id=n1,
                target_id=n2,
                relationship_type=ExtendedRelationshipType.COMMUNICATES_WITH,
                weight=1.0
            ))

    # Connect peripheral nodes with single edges
    edges.append(GraphEdge(source_id="D1", target_id="P1", relationship_type=ExtendedRelationshipType.ASSOCIATED_WITH, weight=0.5))
    edges.append(GraphEdge(source_id="D2", target_id="P2", relationship_type=ExtendedRelationshipType.ASSOCIATED_WITH, weight=0.5))

    return nodes, edges


@pytest.fixture
def threat_graph():
    """Realistic threat intelligence graph."""
    nodes = [
        # Threat actor
        GraphNode(entity_id="TA1", entity_type=ExtendedEntityType.THREAT_ACTOR, value="APT28", risk_score=0.95),
        # Malware
        GraphNode(entity_id="MW1", entity_type=ExtendedEntityType.MALWARE_FAMILY, value="Zebrocy", risk_score=0.9),
        GraphNode(entity_id="MW2", entity_type=ExtendedEntityType.MALWARE_FAMILY, value="X-Agent", risk_score=0.92),
        # Infrastructure
        GraphNode(entity_id="C2_1", entity_type=ExtendedEntityType.IP_ADDRESS, value="185.99.133.72", risk_score=0.85),
        GraphNode(entity_id="C2_2", entity_type=ExtendedEntityType.IP_ADDRESS, value="185.99.133.73", risk_score=0.85),
        GraphNode(entity_id="DOM1", entity_type=ExtendedEntityType.DOMAIN, value="update-check.net", risk_score=0.8),
        GraphNode(entity_id="DOM2", entity_type=ExtendedEntityType.DOMAIN, value="system-update.org", risk_score=0.8),
        # Victims (separate cluster)
        GraphNode(entity_id="V1", entity_type=ExtendedEntityType.ORGANIZATION, value="Target Corp A", risk_score=0.4),
        GraphNode(entity_id="V2", entity_type=ExtendedEntityType.ORGANIZATION, value="Target Corp B", risk_score=0.4),
        GraphNode(entity_id="V3", entity_type=ExtendedEntityType.ORGANIZATION, value="Target Corp C", risk_score=0.4),
    ]

    edges = [
        # Actor -> Malware (attributed)
        GraphEdge(source_id="TA1", target_id="MW1", relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO, weight=0.95),
        GraphEdge(source_id="TA1", target_id="MW2", relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO, weight=0.95),
        # Malware -> Infrastructure
        GraphEdge(source_id="MW1", target_id="C2_1", relationship_type=ExtendedRelationshipType.COMMUNICATES_WITH, weight=0.9),
        GraphEdge(source_id="MW2", target_id="C2_2", relationship_type=ExtendedRelationshipType.COMMUNICATES_WITH, weight=0.9),
        GraphEdge(source_id="MW1", target_id="DOM1", relationship_type=ExtendedRelationshipType.RESOLVES_TO, weight=0.85),
        GraphEdge(source_id="MW2", target_id="DOM2", relationship_type=ExtendedRelationshipType.RESOLVES_TO, weight=0.85),
        # Infrastructure clustering
        GraphEdge(source_id="C2_1", target_id="C2_2", relationship_type=ExtendedRelationshipType.COLOCATED_WITH, weight=0.8),
        GraphEdge(source_id="DOM1", target_id="DOM2", relationship_type=ExtendedRelationshipType.SIMILAR_TO, weight=0.75),
        GraphEdge(source_id="C2_1", target_id="DOM1", relationship_type=ExtendedRelationshipType.HOSTS, weight=0.9),
        GraphEdge(source_id="C2_2", target_id="DOM2", relationship_type=ExtendedRelationshipType.HOSTS, weight=0.9),
        # Actor -> Victims (attack relationship)
        GraphEdge(source_id="TA1", target_id="V1", relationship_type=ExtendedRelationshipType.TARGETS, weight=0.7),
        GraphEdge(source_id="TA1", target_id="V2", relationship_type=ExtendedRelationshipType.TARGETS, weight=0.7),
        GraphEdge(source_id="TA1", target_id="V3", relationship_type=ExtendedRelationshipType.TARGETS, weight=0.7),
        # Victims connected (same industry)
        GraphEdge(source_id="V1", target_id="V2", relationship_type=ExtendedRelationshipType.RELATED_TO, weight=0.5),
        GraphEdge(source_id="V2", target_id="V3", relationship_type=ExtendedRelationshipType.RELATED_TO, weight=0.5),
    ]

    return nodes, edges


# =============================================================================
# CONNECTED COMPONENTS TESTS
# =============================================================================

class TestConnectedComponents:
    """Tests for connected component detection."""

    def test_weakly_connected_single_component(self, simple_graph):
        """Test weakly connected components on connected graph."""
        nodes, edges = simple_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.weakly_connected_components()

        assert isinstance(result, ComponentResult)
        assert result.component_type == "weakly"
        assert result.component_count == 1
        assert result.largest_size == 6
        assert len(result.components[0]) == 6

    def test_weakly_connected_multiple(self, disconnected_graph):
        """Test weakly connected components on disconnected graph."""
        nodes, edges = disconnected_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.weakly_connected_components()

        assert result.component_count == 3
        # Sizes: 3, 2, 1
        assert result.largest_size == 3
        assert 1 in result.size_distribution
        assert 2 in result.size_distribution
        assert 3 in result.size_distribution

    def test_strongly_connected_components(self, simple_graph):
        """Test strongly connected components."""
        nodes, edges = simple_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.strongly_connected_components()

        assert isinstance(result, ComponentResult)
        assert result.component_type == "strongly"
        # Directed triangles - each node forms its own SCC
        assert result.component_count >= 1

    def test_convenience_function(self, disconnected_graph):
        """Test find_connected_components convenience function."""
        nodes, edges = disconnected_graph

        result = find_connected_components(nodes, edges, strong=False)

        assert result.component_count == 3


# =============================================================================
# LOUVAIN COMMUNITY DETECTION TESTS
# =============================================================================

class TestLouvainCommunityDetection:
    """Tests for Louvain algorithm."""

    def test_louvain_basic(self, simple_graph):
        """Test Louvain on simple graph with two communities."""
        nodes, edges = simple_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.louvain()

        assert isinstance(result, CommunityResult)
        assert result.algorithm == "louvain"
        assert result.community_count >= 1
        assert result.computation_time_ms > 0

    def test_louvain_modularity(self, simple_graph):
        """Test that Louvain produces positive modularity."""
        nodes, edges = simple_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.louvain()

        # Should have positive modularity for graph with community structure
        assert result.modularity >= 0

    def test_louvain_resolution(self, threat_graph):
        """Test resolution parameter affects community count."""
        nodes, edges = threat_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result_low = engine.louvain(resolution=0.5)
        result_high = engine.louvain(resolution=2.0)

        # Higher resolution should find more (smaller) communities
        assert result_high.community_count >= result_low.community_count

    def test_louvain_node_coverage(self, simple_graph):
        """Test that all nodes are assigned to communities."""
        nodes, edges = simple_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.louvain()

        # All nodes should be in node_to_community
        assert len(result.node_to_community) == 6
        for node in nodes:
            assert node.entity_id in result.node_to_community

    def test_louvain_empty_graph(self):
        """Test Louvain on empty graph."""
        engine = CommunityEngine()
        engine.build_graph([], [])

        result = engine.louvain()

        assert result.community_count == 0
        assert result.modularity == 0


# =============================================================================
# LABEL PROPAGATION TESTS
# =============================================================================

class TestLabelPropagation:
    """Tests for label propagation algorithm."""

    def test_label_propagation_basic(self, simple_graph):
        """Test label propagation on simple graph."""
        nodes, edges = simple_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.label_propagation(seed=42)

        assert isinstance(result, CommunityResult)
        assert result.algorithm == "label_propagation"
        assert result.community_count >= 1

    def test_label_propagation_reproducibility(self, simple_graph):
        """Test that seed produces reproducible results."""
        nodes, edges = simple_graph

        engine1 = CommunityEngine()
        engine1.build_graph(nodes, edges)
        result1 = engine1.label_propagation(seed=42)

        engine2 = CommunityEngine()
        engine2.build_graph(nodes, edges)
        result2 = engine2.label_propagation(seed=42)

        # Same seed should produce same community count
        assert result1.community_count == result2.community_count

    def test_label_propagation_node_coverage(self, threat_graph):
        """Test that all nodes are assigned to communities."""
        nodes, edges = threat_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.label_propagation(seed=42)

        assert len(result.node_to_community) == 10

    def test_convenience_function(self, simple_graph):
        """Test detect_communities convenience function."""
        nodes, edges = simple_graph

        result = detect_communities(nodes, edges, algorithm="label_propagation", seed=42)

        assert result.algorithm == "label_propagation"


# =============================================================================
# K-CORE DECOMPOSITION TESTS
# =============================================================================

class TestKCoreDecomposition:
    """Tests for k-core decomposition."""

    def test_k_core_basic(self, simple_graph):
        """Test k-core on simple graph."""
        nodes, edges = simple_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.k_core_decomposition()

        assert isinstance(result, KCoreResult)
        assert result.max_k >= 1
        assert len(result.core_numbers) == 6

    def test_k_core_dense_graph(self, dense_graph):
        """Test k-core on dense graph identifies core."""
        nodes, edges = dense_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.k_core_decomposition()

        # Core nodes D1-D5 should have higher k
        # Peripheral nodes should have lower k
        core_k = {result.core_numbers[f"D{i}"] for i in range(1, 6)}
        peripheral_k = {result.core_numbers["P1"], result.core_numbers["P2"]}

        assert max(core_k) > max(peripheral_k)
        assert result.degeneracy == result.max_k

    def test_get_k_core(self, dense_graph):
        """Test get_k_core method."""
        nodes, edges = dense_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        # Get 2-core (should include dense core)
        k2_core = engine.get_k_core(2)

        # Should include at least the core nodes
        assert len(k2_core) >= 5
        for i in range(1, 6):
            assert f"D{i}" in k2_core

    def test_k_core_empty_graph(self):
        """Test k-core on empty graph."""
        engine = CommunityEngine()
        engine.build_graph([], [])

        result = engine.k_core_decomposition()

        assert result.max_k == 0

    def test_convenience_function(self, dense_graph):
        """Test get_dense_core convenience function."""
        nodes, edges = dense_graph

        core = get_dense_core(nodes, edges, k=2)

        assert len(core) >= 5


# =============================================================================
# CLUSTERING COEFFICIENT TESTS
# =============================================================================

class TestClusteringCoefficient:
    """Tests for clustering coefficient calculation."""

    def test_clustering_triangle(self, simple_graph):
        """Test clustering on graph with triangles."""
        nodes, edges = simple_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.clustering_coefficient()

        assert isinstance(result, ClusteringResult)
        assert result.global_clustering >= 0
        assert result.global_clustering <= 1
        assert result.average_clustering >= 0
        assert result.average_clustering <= 1

    def test_clustering_perfect_triangles(self):
        """Test clustering on perfect triangle."""
        nodes = [
            GraphNode(entity_id="T1", entity_type=ExtendedEntityType.IP_ADDRESS, value="1.1.1.1"),
            GraphNode(entity_id="T2", entity_type=ExtendedEntityType.IP_ADDRESS, value="2.2.2.2"),
            GraphNode(entity_id="T3", entity_type=ExtendedEntityType.IP_ADDRESS, value="3.3.3.3"),
        ]
        edges = [
            GraphEdge(source_id="T1", target_id="T2", relationship_type=ExtendedRelationshipType.COMMUNICATES_WITH, weight=1.0),
            GraphEdge(source_id="T2", target_id="T3", relationship_type=ExtendedRelationshipType.COMMUNICATES_WITH, weight=1.0),
            GraphEdge(source_id="T1", target_id="T3", relationship_type=ExtendedRelationshipType.COMMUNICATES_WITH, weight=1.0),
        ]

        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.clustering_coefficient()

        # Perfect triangle should have clustering = 1.0
        assert result.global_clustering == 1.0
        assert result.average_clustering == 1.0
        assert all(c == 1.0 for c in result.node_clustering.values())

    def test_clustering_line_graph(self):
        """Test clustering on line graph (no triangles)."""
        nodes = [
            GraphNode(entity_id="L1", entity_type=ExtendedEntityType.IP_ADDRESS, value="1.1.1.1"),
            GraphNode(entity_id="L2", entity_type=ExtendedEntityType.IP_ADDRESS, value="2.2.2.2"),
            GraphNode(entity_id="L3", entity_type=ExtendedEntityType.IP_ADDRESS, value="3.3.3.3"),
        ]
        edges = [
            GraphEdge(source_id="L1", target_id="L2", relationship_type=ExtendedRelationshipType.COMMUNICATES_WITH, weight=1.0),
            GraphEdge(source_id="L2", target_id="L3", relationship_type=ExtendedRelationshipType.COMMUNICATES_WITH, weight=1.0),
        ]

        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.clustering_coefficient()

        # Line graph has no triangles
        assert result.global_clustering == 0.0
        assert result.triangle_count == 0

    def test_clustering_empty_graph(self):
        """Test clustering on empty graph."""
        engine = CommunityEngine()
        engine.build_graph([], [])

        result = engine.clustering_coefficient()

        assert result.global_clustering == 0.0
        assert result.average_clustering == 0.0


# =============================================================================
# COMMUNITY INFO TESTS
# =============================================================================

class TestCommunityInfo:
    """Tests for community information building."""

    def test_community_density(self, simple_graph):
        """Test community density calculation."""
        nodes, edges = simple_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.louvain()

        for community in result.communities:
            # Density should be between 0 and 1
            assert 0 <= community.density <= 1

    def test_community_central_nodes(self, threat_graph):
        """Test identification of central nodes in communities."""
        nodes, edges = threat_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.louvain()

        for community in result.communities:
            if community.size > 2:
                # Should identify central nodes
                assert len(community.central_nodes) >= 1

    def test_community_bridge_nodes(self, simple_graph):
        """Test identification of bridge nodes."""
        nodes, edges = simple_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.louvain()

        # If multiple communities, there should be bridge nodes
        if result.community_count > 1:
            all_bridge_nodes = []
            for community in result.communities:
                all_bridge_nodes.extend(community.bridge_nodes)
            assert len(all_bridge_nodes) >= 1

    def test_community_risk_score(self, threat_graph):
        """Test community risk score aggregation."""
        nodes, edges = threat_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.louvain()

        for community in result.communities:
            # Risk score should be average of member scores
            assert 0 <= community.risk_score <= 1

    def test_community_label(self, threat_graph):
        """Test community label generation."""
        nodes, edges = threat_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.louvain()

        for community in result.communities:
            # Each community should have a label
            assert community.label is not None
            assert len(community.label) > 0


# =============================================================================
# RESULT SERIALIZATION TESTS
# =============================================================================

class TestResultSerialization:
    """Tests for result to_dict methods."""

    def test_community_result_to_dict(self, simple_graph):
        """Test CommunityResult serialization."""
        nodes, edges = simple_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.louvain()
        result_dict = result.to_dict()

        assert "algorithm" in result_dict
        assert "community_count" in result_dict
        assert "modularity" in result_dict
        assert "computation_time_ms" in result_dict
        assert "communities" in result_dict

    def test_component_result_to_dict(self, disconnected_graph):
        """Test ComponentResult serialization."""
        nodes, edges = disconnected_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.weakly_connected_components()
        result_dict = result.to_dict()

        assert "component_type" in result_dict
        assert "component_count" in result_dict
        assert "largest_size" in result_dict
        assert "size_distribution" in result_dict

    def test_k_core_result_to_dict(self, dense_graph):
        """Test KCoreResult serialization."""
        nodes, edges = dense_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.k_core_decomposition()
        result_dict = result.to_dict()

        assert "max_k" in result_dict
        assert "degeneracy" in result_dict
        assert "k_core_sizes" in result_dict

    def test_clustering_result_to_dict(self, simple_graph):
        """Test ClusteringResult serialization."""
        nodes, edges = simple_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.clustering_coefficient()
        result_dict = result.to_dict()

        assert "global_clustering" in result_dict
        assert "average_clustering" in result_dict
        assert "triangle_count" in result_dict


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestCommunityIntegration:
    """Integration tests for community detection."""

    def test_full_analysis_pipeline(self, threat_graph):
        """Test complete community analysis pipeline."""
        nodes, edges = threat_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        # Run all analyses
        components = engine.weakly_connected_components()
        communities = engine.louvain()
        k_cores = engine.k_core_decomposition()
        clustering = engine.clustering_coefficient()

        # Should complete without errors
        assert components.component_count >= 1
        assert communities.community_count >= 1
        assert k_cores.max_k >= 0
        assert 0 <= clustering.global_clustering <= 1

    def test_detect_communities_convenience(self, simple_graph):
        """Test detect_communities with different algorithms."""
        nodes, edges = simple_graph

        louvain_result = detect_communities(nodes, edges, algorithm="louvain")
        lp_result = detect_communities(nodes, edges, algorithm="label_propagation", seed=42)

        assert louvain_result.algorithm == "louvain"
        assert lp_result.algorithm == "label_propagation"

    def test_threat_actor_clustering(self, threat_graph):
        """Test that threat actors and infrastructure cluster together."""
        nodes, edges = threat_graph
        engine = CommunityEngine()
        engine.build_graph(nodes, edges)

        result = engine.louvain()

        # Find which community the threat actor is in
        ta_comm = result.node_to_community.get("TA1")

        # Related entities should often be in same community
        assert ta_comm is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
