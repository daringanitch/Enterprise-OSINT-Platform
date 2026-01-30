#!/usr/bin/env python3
"""
Tests for Graph Intelligence Models

Validates GraphNode, GraphEdge, and related data structures.
"""

import pytest
from datetime import datetime, timedelta
from graph_intelligence.models import (
    ExtendedEntityType,
    ExtendedRelationshipType,
    GraphNode,
    GraphEdge,
    CentralityScores,
    CommunityInfo,
    PathResult,
    SimilarityResult,
    LinkPrediction,
    AnomalyResult,
    PropagationResult,
    QueryResult,
    PatternMatch,
    VisNode,
    VisEdge,
    GraphVisualization,
    GraphStatistics,
    GraphConfig,
    GraphOperation,
)


class TestExtendedEntityType:
    """Tests for ExtendedEntityType enum."""

    def test_basic_entity_types(self):
        """Test core entity types exist."""
        assert ExtendedEntityType.DOMAIN.value == "domain"
        assert ExtendedEntityType.IP_ADDRESS.value == "ip_address"
        assert ExtendedEntityType.EMAIL.value == "email"
        assert ExtendedEntityType.PERSON.value == "person"
        assert ExtendedEntityType.ORGANIZATION.value == "organization"

    def test_extended_entity_types(self):
        """Test new extended entity types."""
        assert ExtendedEntityType.THREAT_ACTOR.value == "threat_actor"
        assert ExtendedEntityType.CAMPAIGN.value == "campaign"
        assert ExtendedEntityType.MALWARE_FAMILY.value == "malware_family"
        assert ExtendedEntityType.VULNERABILITY.value == "vulnerability"
        assert ExtendedEntityType.CRYPTOCURRENCY_WALLET.value == "crypto_wallet"
        assert ExtendedEntityType.LOCATION.value == "location"

    def test_from_string(self):
        """Test string to enum conversion."""
        assert ExtendedEntityType.from_string("domain") == ExtendedEntityType.DOMAIN
        assert ExtendedEntityType.from_string("DOMAIN") == ExtendedEntityType.DOMAIN
        assert ExtendedEntityType.from_string("ip") == ExtendedEntityType.IP_ADDRESS
        assert ExtendedEntityType.from_string("cve") == ExtendedEntityType.VULNERABILITY
        assert ExtendedEntityType.from_string("apt") == ExtendedEntityType.THREAT_ACTOR

    def test_category(self):
        """Test entity type categories."""
        assert ExtendedEntityType.DOMAIN.category == "infrastructure"
        assert ExtendedEntityType.IP_ADDRESS.category == "infrastructure"
        assert ExtendedEntityType.PERSON.category == "identity"
        assert ExtendedEntityType.THREAT_ACTOR.category == "threat"
        assert ExtendedEntityType.ORGANIZATION.category == "business"
        assert ExtendedEntityType.CRYPTOCURRENCY_WALLET.category == "financial"
        assert ExtendedEntityType.LOCATION.category == "geospatial"

    def test_icon(self):
        """Test entity type icons."""
        assert ExtendedEntityType.DOMAIN.icon == "globe"
        assert ExtendedEntityType.IP_ADDRESS.icon == "server"
        assert ExtendedEntityType.THREAT_ACTOR.icon == "skull"
        assert ExtendedEntityType.MALWARE_FAMILY.icon == "bug"

    def test_color(self):
        """Test entity type colors."""
        assert ExtendedEntityType.DOMAIN.color == "#3B82F6"  # Blue for infrastructure
        assert ExtendedEntityType.THREAT_ACTOR.color == "#EF4444"  # Red for threat


class TestExtendedRelationshipType:
    """Tests for ExtendedRelationshipType enum."""

    def test_basic_relationship_types(self):
        """Test core relationship types exist."""
        assert ExtendedRelationshipType.RESOLVES_TO.value == "resolves_to"
        assert ExtendedRelationshipType.HOSTS.value == "hosts"
        assert ExtendedRelationshipType.OWNS.value == "owns"
        assert ExtendedRelationshipType.ASSOCIATED_WITH.value == "associated_with"

    def test_extended_relationship_types(self):
        """Test new extended relationship types."""
        assert ExtendedRelationshipType.ATTRIBUTED_TO.value == "attributed_to"
        assert ExtendedRelationshipType.COMMUNICATES_WITH.value == "communicates_with"
        assert ExtendedRelationshipType.TRANSACTS_WITH.value == "transacts_with"
        assert ExtendedRelationshipType.IMPERSONATES.value == "impersonates"

    def test_from_string(self):
        """Test string to enum conversion."""
        assert ExtendedRelationshipType.from_string("resolves_to") == ExtendedRelationshipType.RESOLVES_TO
        assert ExtendedRelationshipType.from_string("unknown") == ExtendedRelationshipType.ASSOCIATED_WITH

    def test_is_directional(self):
        """Test directional relationship detection."""
        assert ExtendedRelationshipType.RESOLVES_TO.is_directional is True
        assert ExtendedRelationshipType.ATTRIBUTED_TO.is_directional is True
        assert ExtendedRelationshipType.ASSOCIATED_WITH.is_directional is False
        assert ExtendedRelationshipType.SIMILAR_TO.is_directional is False

    def test_inverse(self):
        """Test inverse relationship lookup."""
        assert ExtendedRelationshipType.RESOLVES_TO.inverse == ExtendedRelationshipType.HOSTS
        assert ExtendedRelationshipType.HOSTS.inverse == ExtendedRelationshipType.RESOLVES_TO
        assert ExtendedRelationshipType.PRECEDED_BY.inverse == ExtendedRelationshipType.FOLLOWED_BY

    def test_weight_default(self):
        """Test default weights."""
        assert ExtendedRelationshipType.RESOLVES_TO.weight_default == 1.0
        assert ExtendedRelationshipType.ASSOCIATED_WITH.weight_default == 0.7
        assert ExtendedRelationshipType.MENTIONS.weight_default == 0.5


class TestGraphNode:
    """Tests for GraphNode model."""

    def test_create_basic_node(self):
        """Test basic node creation."""
        node = GraphNode(
            value="example.com",
            entity_type=ExtendedEntityType.DOMAIN,
        )

        assert node.value == "example.com"
        assert node.entity_type == ExtendedEntityType.DOMAIN
        assert node.normalized_value == "example.com"
        assert node.node_id is not None
        assert node.entity_id is not None
        assert node.confidence == 0.5

    def test_normalize_domain(self):
        """Test domain normalization."""
        node = GraphNode(
            value="WWW.Example.COM",
            entity_type=ExtendedEntityType.DOMAIN,
        )

        assert node.normalized_value == "example.com"

    def test_normalize_email(self):
        """Test email normalization."""
        node = GraphNode(
            value="User@Example.COM",
            entity_type=ExtendedEntityType.EMAIL,
        )

        assert node.normalized_value == "user@example.com"

    def test_generate_label(self):
        """Test label generation."""
        threat_actor = GraphNode(
            value="APT28",
            entity_type=ExtendedEntityType.THREAT_ACTOR,
        )
        assert threat_actor.label == "Actor: APT28"

        malware = GraphNode(
            value="Emotet",
            entity_type=ExtendedEntityType.MALWARE_FAMILY,
        )
        assert malware.label == "Malware: Emotet"

    def test_add_source(self):
        """Test adding sources increases confidence."""
        node = GraphNode(
            value="test.com",
            entity_type=ExtendedEntityType.DOMAIN,
        )

        initial_confidence = node.confidence
        node.add_source("virustotal")
        assert node.confidence > initial_confidence
        assert "virustotal" in node.sources

        # Adding same source again shouldn't change confidence
        confidence_after_first = node.confidence
        node.add_source("virustotal")
        assert node.confidence == confidence_after_first

    def test_add_tag(self):
        """Test adding tags."""
        node = GraphNode(
            value="evil.com",
            entity_type=ExtendedEntityType.DOMAIN,
        )

        node.add_tag("malicious")
        assert "malicious" in node.tags

        # Adding same tag again shouldn't duplicate
        node.add_tag("malicious")
        assert node.tags.count("malicious") == 1

    def test_add_investigation(self):
        """Test investigation linkage."""
        node = GraphNode(
            value="target.com",
            entity_type=ExtendedEntityType.DOMAIN,
        )

        node.add_investigation("inv-001")
        assert "inv-001" in node.investigation_ids

    def test_merge_from(self):
        """Test merging nodes."""
        node1 = GraphNode(
            value="test.com",
            entity_type=ExtendedEntityType.DOMAIN,
            sources=["source1"],
            tags=["tag1"],
        )
        node1.first_seen = datetime(2024, 1, 1)

        node2 = GraphNode(
            value="test.com",
            entity_type=ExtendedEntityType.DOMAIN,
            sources=["source2"],
            tags=["tag2"],
        )
        node2.first_seen = datetime(2023, 1, 1)
        node2.properties = {"key": "value"}

        node1.merge_from(node2)

        assert "source1" in node1.sources
        assert "source2" in node1.sources
        assert "tag1" in node1.tags
        assert "tag2" in node1.tags
        assert node1.first_seen == datetime(2023, 1, 1)  # Earlier date
        assert node1.properties.get("key") == "value"
        assert node1.version == 2

    def test_total_degree(self):
        """Test total degree calculation."""
        node = GraphNode(
            value="hub.com",
            entity_type=ExtendedEntityType.DOMAIN,
        )
        node.in_degree = 10
        node.out_degree = 5

        assert node.total_degree == 15

    def test_centrality_score(self):
        """Test composite centrality score."""
        node = GraphNode(
            value="important.com",
            entity_type=ExtendedEntityType.DOMAIN,
        )
        node.pagerank = 0.5
        node.betweenness_centrality = 0.4
        node.degree_centrality = 0.3
        node.eigenvector_centrality = 0.2

        expected = 0.5 * 0.3 + 0.4 * 0.3 + 0.3 * 0.2 + 0.2 * 0.2
        assert abs(node.centrality_score - expected) < 0.0001

    def test_to_dict(self):
        """Test dictionary serialization."""
        node = GraphNode(
            value="test.com",
            entity_type=ExtendedEntityType.DOMAIN,
        )

        data = node.to_dict()

        assert data["value"] == "test.com"
        assert data["entity_type"] == "domain"
        assert "node_id" in data
        assert "centrality" in data
        assert "pagerank" in data["centrality"]

    def test_to_neo4j_properties(self):
        """Test Neo4j property conversion."""
        node = GraphNode(
            value="test.com",
            entity_type=ExtendedEntityType.DOMAIN,
        )

        props = node.to_neo4j_properties()

        assert props["value"] == "test.com"
        assert props["entity_type"] == "domain"
        assert isinstance(props["sources"], list)
        assert isinstance(props["tags"], list)


class TestGraphEdge:
    """Tests for GraphEdge model."""

    def test_create_basic_edge(self):
        """Test basic edge creation."""
        edge = GraphEdge(
            source_id="node1",
            target_id="node2",
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
        )

        assert edge.source_id == "node1"
        assert edge.target_id == "node2"
        assert edge.relationship_type == ExtendedRelationshipType.RESOLVES_TO
        assert edge.edge_id is not None
        assert edge.active is True

    def test_bidirectional_auto_set(self):
        """Test bidirectional flag auto-setting."""
        directional = GraphEdge(
            source_id="a",
            target_id="b",
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
        )
        assert directional.bidirectional is False

        bidirectional = GraphEdge(
            source_id="a",
            target_id="b",
            relationship_type=ExtendedRelationshipType.ASSOCIATED_WITH,
        )
        assert bidirectional.bidirectional is True

    def test_default_weight(self):
        """Test default weight from relationship type."""
        high_weight = GraphEdge(
            source_id="a",
            target_id="b",
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
        )
        assert high_weight.weight == 1.0

        medium_weight = GraphEdge(
            source_id="a",
            target_id="b",
            relationship_type=ExtendedRelationshipType.ASSOCIATED_WITH,
        )
        assert medium_weight.weight == 0.7

    def test_composite_weight(self):
        """Test composite weight calculation."""
        edge = GraphEdge(
            source_id="a",
            target_id="b",
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
        )
        edge.weight = 0.8
        edge.confidence = 0.5

        assert edge.composite_weight == 0.4

    def test_add_source(self):
        """Test adding sources."""
        edge = GraphEdge(
            source_id="a",
            target_id="b",
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
        )

        initial_confidence = edge.confidence
        edge.add_source("dns_records")
        assert edge.confidence > initial_confidence
        assert "dns_records" in edge.sources

    def test_add_evidence(self):
        """Test adding evidence."""
        edge = GraphEdge(
            source_id="a",
            target_id="b",
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
        )

        evidence = {"type": "dns_lookup", "timestamp": "2024-01-01"}
        edge.add_evidence(evidence)

        assert len(edge.evidence) == 1
        assert edge.evidence[0]["type"] == "dns_lookup"

    def test_merge_from(self):
        """Test merging edges."""
        edge1 = GraphEdge(
            source_id="a",
            target_id="b",
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
            sources=["source1"],
        )
        edge1.first_observed = datetime(2024, 1, 1)
        edge1.weight = 0.8

        edge2 = GraphEdge(
            source_id="a",
            target_id="b",
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
            sources=["source2"],
        )
        edge2.first_observed = datetime(2023, 1, 1)
        edge2.weight = 0.6

        edge1.merge_from(edge2)

        assert "source1" in edge1.sources
        assert "source2" in edge1.sources
        assert edge1.first_observed == datetime(2023, 1, 1)
        assert edge1.weight == 0.7  # Average of 0.8 and 0.6
        assert edge1.version == 2

    def test_to_dict(self):
        """Test dictionary serialization."""
        edge = GraphEdge(
            source_id="node1",
            target_id="node2",
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
        )

        data = edge.to_dict()

        assert data["source_id"] == "node1"
        assert data["target_id"] == "node2"
        assert data["relationship_type"] == "resolves_to"
        assert "composite_weight" in data


class TestCentralityScores:
    """Tests for CentralityScores model."""

    def test_create_scores(self):
        """Test creating centrality scores."""
        scores = CentralityScores(
            node_id="node1",
            entity_id="entity1",
            degree=0.5,
            betweenness=0.3,
            pagerank=0.4,
            eigenvector=0.2,
        )

        assert scores.node_id == "node1"
        assert scores.degree == 0.5
        assert scores.betweenness == 0.3

    def test_composite_score(self):
        """Test composite score calculation."""
        scores = CentralityScores(
            node_id="node1",
            entity_id="entity1",
            degree=1.0,
            betweenness=1.0,
            pagerank=1.0,
            eigenvector=1.0,
        )

        assert scores.composite == 1.0

    def test_to_dict(self):
        """Test serialization."""
        scores = CentralityScores(
            node_id="node1",
            entity_id="entity1",
            pagerank=0.12345,
        )

        data = scores.to_dict()
        assert data["pagerank"] == 0.1235  # Rounded to 4 decimal places


class TestCommunityInfo:
    """Tests for CommunityInfo model."""

    def test_create_community(self):
        """Test creating community info."""
        community = CommunityInfo(
            community_id="comm1",
            size=10,
            density=0.45,
            modularity_contribution=0.12,
            member_ids=["n1", "n2", "n3"],
            central_nodes=["n1"],
        )

        assert community.community_id == "comm1"
        assert community.size == 10
        assert len(community.member_ids) == 3

    def test_to_dict(self):
        """Test serialization."""
        community = CommunityInfo(
            community_id="comm1",
            size=100,
            density=0.5,
            modularity_contribution=0.1,
        )

        data = community.to_dict()
        assert data["community_id"] == "comm1"
        assert data["member_count"] == 0


class TestPathResult:
    """Tests for PathResult model."""

    def test_create_found_path(self):
        """Test creating a found path."""
        path = PathResult(
            found=True,
            source_id="a",
            target_id="b",
            path_length=2,
            nodes=[{"id": "a"}, {"id": "c"}, {"id": "b"}],
            edges=[{"type": "rel1"}, {"type": "rel2"}],
            total_confidence=0.8,
        )

        assert path.found is True
        assert path.path_length == 2
        assert len(path.nodes) == 3

    def test_create_not_found_path(self):
        """Test creating a not-found path."""
        path = PathResult(
            found=False,
            source_id="a",
            target_id="b",
        )

        assert path.found is False
        assert path.path_length == 0


class TestAnomalyResult:
    """Tests for AnomalyResult model."""

    def test_severity_levels(self):
        """Test severity calculation."""
        critical = AnomalyResult(
            node_id="n1",
            anomaly_type="outlier",
            anomaly_score=0.95,
        )
        assert critical.severity == "critical"

        high = AnomalyResult(
            node_id="n1",
            anomaly_type="outlier",
            anomaly_score=0.75,
        )
        assert high.severity == "high"

        medium = AnomalyResult(
            node_id="n1",
            anomaly_type="outlier",
            anomaly_score=0.55,
        )
        assert medium.severity == "medium"

        low = AnomalyResult(
            node_id="n1",
            anomaly_type="outlier",
            anomaly_score=0.3,
        )
        assert low.severity == "low"


class TestSimilarityResult:
    """Tests for SimilarityResult model."""

    def test_combined_similarity(self):
        """Test combined similarity calculation."""
        result = SimilarityResult(
            node_id="a",
            compared_to_id="b",
            jaccard_similarity=0.6,
            cosine_similarity=0.8,
        )

        assert result.combined_similarity == 0.7


class TestLinkPrediction:
    """Tests for LinkPrediction model."""

    def test_create_prediction(self):
        """Test creating a link prediction."""
        prediction = LinkPrediction(
            source_id="a",
            target_id="b",
            predicted_relationship=ExtendedRelationshipType.ASSOCIATED_WITH,
            probability=0.85,
            common_neighbors=5,
        )

        assert prediction.probability == 0.85
        assert prediction.common_neighbors == 5


class TestVisualizationModels:
    """Tests for visualization models."""

    def test_vis_node_from_graph_node(self):
        """Test VisNode creation from GraphNode."""
        graph_node = GraphNode(
            value="test.com",
            entity_type=ExtendedEntityType.DOMAIN,
        )
        graph_node.pagerank = 0.5

        vis_node = VisNode.from_graph_node(graph_node)

        assert vis_node.id == graph_node.entity_id
        assert vis_node.label == "test.com"
        assert vis_node.entity_type == "domain"
        assert vis_node.color == ExtendedEntityType.DOMAIN.color

    def test_vis_edge_from_graph_edge(self):
        """Test VisEdge creation from GraphEdge."""
        graph_edge = GraphEdge(
            source_id="a",
            target_id="b",
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
        )
        graph_edge.confidence = 0.9

        vis_edge = VisEdge.from_graph_edge(graph_edge)

        assert vis_edge.source == "a"
        assert vis_edge.target == "b"
        assert vis_edge.relationship_type == "resolves_to"
        assert vis_edge.animated is True  # High confidence + active

    def test_graph_visualization(self):
        """Test GraphVisualization creation."""
        viz = GraphVisualization(
            nodes=[
                VisNode(id="a", label="A", entity_type="domain"),
                VisNode(id="b", label="B", entity_type="ip_address"),
            ],
            edges=[
                VisEdge(id="e1", source="a", target="b", relationship_type="resolves_to"),
            ],
        )

        data = viz.to_dict()

        assert len(data["nodes"]) == 2
        assert len(data["edges"]) == 1
        assert data["metadata"]["total_nodes"] == 2


class TestGraphStatistics:
    """Tests for GraphStatistics model."""

    def test_create_statistics(self):
        """Test creating graph statistics."""
        stats = GraphStatistics(
            total_nodes=1000,
            total_edges=5000,
            density=0.01,
            average_degree=10.0,
            clustering_coefficient=0.35,
            communities_count=25,
        )

        assert stats.total_nodes == 1000
        assert stats.total_edges == 5000

    def test_to_dict(self):
        """Test serialization includes all fields."""
        stats = GraphStatistics(
            total_nodes=100,
            high_risk_nodes=10,
            medium_risk_nodes=30,
            low_risk_nodes=60,
        )

        data = stats.to_dict()

        assert "risk_distribution" in data
        assert data["risk_distribution"]["high"] == 10


class TestGraphConfig:
    """Tests for GraphConfig model."""

    def test_default_config(self):
        """Test default configuration values."""
        config = GraphConfig()

        assert config.neo4j_uri == "bolt://localhost:7687"
        assert config.redis_port == 6379
        assert config.max_path_depth == 6

    def test_to_dict(self):
        """Test config serialization (should not include password)."""
        config = GraphConfig(neo4j_password="secret")

        data = config.to_dict()

        # Password should not be in output
        assert "neo4j_password" not in data


class TestGraphOperation:
    """Tests for GraphOperation model."""

    def test_create_operation(self):
        """Test creating an operation record."""
        op = GraphOperation(
            operation_type="create",
            entity_ids=["e1", "e2"],
            user_id="user1",
        )

        assert op.operation_type == "create"
        assert op.status == "pending"
        assert op.operation_id is not None

    def test_to_dict_limits_entity_ids(self):
        """Test that to_dict limits entity_ids in output."""
        op = GraphOperation(
            operation_type="bulk_update",
            entity_ids=[f"e{i}" for i in range(100)],
        )

        data = op.to_dict()

        assert len(data["entity_ids"]) == 10  # Limited to 10
        assert data["entity_count"] == 100  # But count is accurate
