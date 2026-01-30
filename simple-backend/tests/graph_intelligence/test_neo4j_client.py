#!/usr/bin/env python3
"""
Tests for Neo4j Graph Client

Tests the GraphClient with mock mode (no Neo4j required).
"""

import pytest
from datetime import datetime
from graph_intelligence import (
    GraphClient,
    GraphConfig,
    GraphNode,
    GraphEdge,
    ExtendedEntityType,
    ExtendedRelationshipType,
    create_graph_client,
)


@pytest.fixture
def client():
    """Create a GraphClient in mock mode."""
    config = GraphConfig(
        neo4j_uri="bolt://localhost:7687",
        neo4j_username="neo4j",
        neo4j_password="",  # Empty password forces mock mode
    )
    return GraphClient(config)


@pytest.fixture
def sample_nodes():
    """Create sample nodes for testing."""
    return [
        GraphNode(
            value="evil.com",
            entity_type=ExtendedEntityType.DOMAIN,
            sources=["virustotal"],
        ),
        GraphNode(
            value="192.168.1.1",
            entity_type=ExtendedEntityType.IP_ADDRESS,
            sources=["shodan"],
        ),
        GraphNode(
            value="APT28",
            entity_type=ExtendedEntityType.THREAT_ACTOR,
            sources=["mitre"],
        ),
        GraphNode(
            value="attacker@evil.com",
            entity_type=ExtendedEntityType.EMAIL,
            sources=["whois"],
        ),
    ]


class TestGraphClientConnection:
    """Tests for client connection."""

    def test_client_creation(self, client):
        """Test client can be created."""
        assert client is not None
        assert client.is_connected

    def test_mock_mode_enabled(self, client):
        """Test that mock mode is enabled when Neo4j unavailable."""
        assert client.is_mock_mode

    def test_create_graph_client_factory(self):
        """Test factory function."""
        client = create_graph_client()
        assert client is not None
        assert client.is_mock_mode


class TestNodeOperations:
    """Tests for node CRUD operations."""

    def test_create_node(self, client, sample_nodes):
        """Test creating a node."""
        node = sample_nodes[0]
        created = client.create_node(node)

        assert created.entity_id == node.entity_id
        assert created.value == "evil.com"

    def test_get_node(self, client, sample_nodes):
        """Test retrieving a node."""
        node = sample_nodes[0]
        client.create_node(node)

        retrieved = client.get_node(node.entity_id)

        assert retrieved is not None
        assert retrieved.value == node.value
        assert retrieved.entity_type == node.entity_type

    def test_get_nonexistent_node(self, client):
        """Test retrieving a node that doesn't exist."""
        result = client.get_node("nonexistent-id")
        assert result is None

    def test_update_node(self, client, sample_nodes):
        """Test updating a node."""
        node = sample_nodes[0]
        client.create_node(node)

        # Update the node
        node.add_source("abuseipdb")
        node.add_tag("malicious")
        updated = client.update_node(node)

        assert "abuseipdb" in updated.sources
        assert "malicious" in updated.tags
        assert updated.version == 2

    def test_upsert_node_create(self, client, sample_nodes):
        """Test upsert creates new node."""
        node = sample_nodes[0]
        result = client.upsert_node(node)

        assert result.entity_id == node.entity_id

    def test_upsert_node_merge(self, client, sample_nodes):
        """Test upsert merges existing node."""
        node1 = sample_nodes[0]
        client.create_node(node1)

        # Create a "duplicate" with additional data
        node2 = GraphNode(
            value="evil.com",
            entity_type=ExtendedEntityType.DOMAIN,
            sources=["new_source"],
            tags=["new_tag"],
        )

        result = client.upsert_node(node2)

        assert "virustotal" in result.sources  # Original source
        assert "new_source" in result.sources  # New source
        assert "new_tag" in result.tags

    def test_delete_node(self, client, sample_nodes):
        """Test deleting a node."""
        node = sample_nodes[0]
        client.create_node(node)

        deleted = client.delete_node(node.entity_id)
        assert deleted is True

        # Verify it's gone
        result = client.get_node(node.entity_id)
        assert result is None

    def test_delete_nonexistent_node(self, client):
        """Test deleting a node that doesn't exist."""
        deleted = client.delete_node("nonexistent-id")
        assert deleted is False

    def test_get_nodes_by_type(self, client, sample_nodes):
        """Test retrieving nodes by entity type."""
        # Create multiple nodes
        for node in sample_nodes:
            client.create_node(node)

        domains = client.get_nodes_by_type(ExtendedEntityType.DOMAIN)
        assert len(domains) == 1
        assert domains[0].value == "evil.com"

        ips = client.get_nodes_by_type(ExtendedEntityType.IP_ADDRESS)
        assert len(ips) == 1
        assert ips[0].value == "192.168.1.1"

    def test_get_nodes_by_investigation(self, client, sample_nodes):
        """Test retrieving nodes by investigation ID."""
        inv_id = "inv-001"

        # Create nodes and link to investigation
        for node in sample_nodes[:2]:
            node.add_investigation(inv_id)
            client.create_node(node)

        # Create one without investigation link
        client.create_node(sample_nodes[2])

        results = client.get_nodes_by_investigation(inv_id)
        assert len(results) == 2

    def test_search_nodes(self, client, sample_nodes):
        """Test searching nodes by value."""
        for node in sample_nodes:
            client.create_node(node)

        # Search for "evil"
        results = client.search_nodes("evil")
        assert len(results) == 2  # evil.com and attacker@evil.com

        # Search with type filter
        domains = client.search_nodes("evil", entity_type=ExtendedEntityType.DOMAIN)
        assert len(domains) == 1
        assert domains[0].value == "evil.com"


class TestEdgeOperations:
    """Tests for edge CRUD operations."""

    def test_create_edge(self, client, sample_nodes):
        """Test creating an edge."""
        # Create nodes first
        domain = sample_nodes[0]
        ip = sample_nodes[1]
        client.create_node(domain)
        client.create_node(ip)

        # Create edge
        edge = GraphEdge(
            source_id=domain.entity_id,
            target_id=ip.entity_id,
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
            sources=["dns"],
        )

        created = client.create_edge(edge)
        assert created.edge_id == edge.edge_id

    def test_get_edge(self, client, sample_nodes):
        """Test retrieving an edge."""
        domain = sample_nodes[0]
        ip = sample_nodes[1]
        client.create_node(domain)
        client.create_node(ip)

        edge = GraphEdge(
            source_id=domain.entity_id,
            target_id=ip.entity_id,
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
        )
        client.create_edge(edge)

        retrieved = client.get_edge(domain.entity_id, ip.entity_id)
        assert retrieved is not None
        assert retrieved.relationship_type == ExtendedRelationshipType.RESOLVES_TO

    def test_get_edge_with_type_filter(self, client, sample_nodes):
        """Test retrieving an edge with type filter."""
        domain = sample_nodes[0]
        ip = sample_nodes[1]
        client.create_node(domain)
        client.create_node(ip)

        edge = GraphEdge(
            source_id=domain.entity_id,
            target_id=ip.entity_id,
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
        )
        client.create_edge(edge)

        # Should find with matching type
        found = client.get_edge(
            domain.entity_id,
            ip.entity_id,
            ExtendedRelationshipType.RESOLVES_TO
        )
        assert found is not None

        # Should not find with different type
        not_found = client.get_edge(
            domain.entity_id,
            ip.entity_id,
            ExtendedRelationshipType.OWNS
        )
        assert not_found is None

    def test_get_edges_for_node(self, client, sample_nodes):
        """Test getting all edges for a node."""
        domain = sample_nodes[0]
        ip = sample_nodes[1]
        actor = sample_nodes[2]
        client.create_node(domain)
        client.create_node(ip)
        client.create_node(actor)

        # Create edges
        edge1 = GraphEdge(
            source_id=domain.entity_id,
            target_id=ip.entity_id,
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
        )
        edge2 = GraphEdge(
            source_id=actor.entity_id,
            target_id=domain.entity_id,
            relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO,
        )
        client.create_edge(edge1)
        client.create_edge(edge2)

        # Get all edges for domain
        edges = client.get_edges_for_node(domain.entity_id, direction="both")
        assert len(edges) == 2

        # Get outgoing edges only
        out_edges = client.get_edges_for_node(domain.entity_id, direction="out")
        assert len(out_edges) == 1
        assert out_edges[0].relationship_type == ExtendedRelationshipType.RESOLVES_TO

    def test_update_edge(self, client, sample_nodes):
        """Test updating an edge."""
        domain = sample_nodes[0]
        ip = sample_nodes[1]
        client.create_node(domain)
        client.create_node(ip)

        edge = GraphEdge(
            source_id=domain.entity_id,
            target_id=ip.entity_id,
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
        )
        client.create_edge(edge)

        # Update edge
        edge.add_source("passive_dns")
        edge.confidence = 0.95
        updated = client.update_edge(edge)

        assert "passive_dns" in updated.sources
        assert updated.confidence == 0.95
        assert updated.version == 2

    def test_upsert_edge(self, client, sample_nodes):
        """Test upserting an edge."""
        domain = sample_nodes[0]
        ip = sample_nodes[1]
        client.create_node(domain)
        client.create_node(ip)

        edge1 = GraphEdge(
            source_id=domain.entity_id,
            target_id=ip.entity_id,
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
            sources=["source1"],
        )
        client.upsert_edge(edge1)

        # Upsert again with new data
        edge2 = GraphEdge(
            source_id=domain.entity_id,
            target_id=ip.entity_id,
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
            sources=["source2"],
        )
        result = client.upsert_edge(edge2)

        assert "source1" in result.sources
        assert "source2" in result.sources

    def test_delete_edge(self, client, sample_nodes):
        """Test deleting an edge."""
        domain = sample_nodes[0]
        ip = sample_nodes[1]
        client.create_node(domain)
        client.create_node(ip)

        edge = GraphEdge(
            source_id=domain.entity_id,
            target_id=ip.entity_id,
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
        )
        client.create_edge(edge)

        deleted = client.delete_edge(domain.entity_id, ip.entity_id)
        assert deleted is True

        # Verify it's gone
        result = client.get_edge(domain.entity_id, ip.entity_id)
        assert result is None


class TestBatchOperations:
    """Tests for batch operations."""

    def test_batch_create_nodes(self, client, sample_nodes):
        """Test batch node creation."""
        created = client.batch_create_nodes(sample_nodes)
        assert created == len(sample_nodes)

        # Verify all nodes exist
        for node in sample_nodes:
            result = client.get_node(node.entity_id)
            assert result is not None

    def test_batch_create_edges(self, client, sample_nodes):
        """Test batch edge creation."""
        # Create nodes first
        client.batch_create_nodes(sample_nodes)

        # Create edges
        edges = [
            GraphEdge(
                source_id=sample_nodes[0].entity_id,
                target_id=sample_nodes[1].entity_id,
                relationship_type=ExtendedRelationshipType.RESOLVES_TO,
            ),
            GraphEdge(
                source_id=sample_nodes[2].entity_id,
                target_id=sample_nodes[0].entity_id,
                relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO,
            ),
            GraphEdge(
                source_id=sample_nodes[3].entity_id,
                target_id=sample_nodes[0].entity_id,
                relationship_type=ExtendedRelationshipType.REGISTERED_BY,
            ),
        ]

        created = client.batch_create_edges(edges)
        assert created == 3

    def test_batch_upsert_nodes(self, client, sample_nodes):
        """Test batch node upsert."""
        # Create initial nodes
        client.batch_create_nodes(sample_nodes[:2])

        # Upsert all nodes (2 existing + 2 new)
        for node in sample_nodes:
            node.add_source("batch_source")

        upserted = client.batch_upsert_nodes(sample_nodes)
        assert upserted == len(sample_nodes)

        # Verify merged data
        node = client.get_node(sample_nodes[0].entity_id)
        assert "batch_source" in node.sources


class TestNeighborQueries:
    """Tests for neighbor queries."""

    def test_get_neighbors_depth_1(self, client, sample_nodes):
        """Test getting immediate neighbors."""
        # Create nodes
        client.batch_create_nodes(sample_nodes)

        # Create edges: domain -> ip, actor -> domain
        edges = [
            GraphEdge(
                source_id=sample_nodes[0].entity_id,  # domain
                target_id=sample_nodes[1].entity_id,  # ip
                relationship_type=ExtendedRelationshipType.RESOLVES_TO,
            ),
            GraphEdge(
                source_id=sample_nodes[2].entity_id,  # actor
                target_id=sample_nodes[0].entity_id,  # domain
                relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO,
            ),
        ]
        client.batch_create_edges(edges)

        # Get neighbors of domain (depth 1)
        nodes, edges_result = client.get_neighbors(sample_nodes[0].entity_id, depth=1)

        assert len(nodes) == 2  # ip and actor
        assert len(edges_result) == 2

    def test_get_neighbors_with_type_filter(self, client, sample_nodes):
        """Test getting neighbors with relationship type filter."""
        client.batch_create_nodes(sample_nodes)

        edges = [
            GraphEdge(
                source_id=sample_nodes[0].entity_id,
                target_id=sample_nodes[1].entity_id,
                relationship_type=ExtendedRelationshipType.RESOLVES_TO,
            ),
            GraphEdge(
                source_id=sample_nodes[2].entity_id,
                target_id=sample_nodes[0].entity_id,
                relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO,
            ),
        ]
        client.batch_create_edges(edges)

        # Get only RESOLVES_TO neighbors
        nodes, _ = client.get_neighbors(
            sample_nodes[0].entity_id,
            depth=1,
            relationship_types=[ExtendedRelationshipType.RESOLVES_TO]
        )

        assert len(nodes) == 1
        assert nodes[0].entity_type == ExtendedEntityType.IP_ADDRESS

    def test_get_neighbors_with_entity_type_filter(self, client, sample_nodes):
        """Test getting neighbors with entity type filter."""
        client.batch_create_nodes(sample_nodes)

        edges = [
            GraphEdge(
                source_id=sample_nodes[0].entity_id,
                target_id=sample_nodes[1].entity_id,
                relationship_type=ExtendedRelationshipType.RESOLVES_TO,
            ),
            GraphEdge(
                source_id=sample_nodes[2].entity_id,
                target_id=sample_nodes[0].entity_id,
                relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO,
            ),
        ]
        client.batch_create_edges(edges)

        # Get only THREAT_ACTOR neighbors
        nodes, _ = client.get_neighbors(
            sample_nodes[0].entity_id,
            depth=1,
            entity_types=[ExtendedEntityType.THREAT_ACTOR]
        )

        assert len(nodes) == 1
        assert nodes[0].entity_type == ExtendedEntityType.THREAT_ACTOR


class TestStatistics:
    """Tests for graph statistics."""

    def test_get_statistics_empty(self, client):
        """Test statistics on empty graph."""
        stats = client.get_statistics()

        assert stats.total_nodes == 0
        assert stats.total_edges == 0
        assert stats.density == 0

    def test_get_statistics_with_data(self, client, sample_nodes):
        """Test statistics with nodes and edges."""
        client.batch_create_nodes(sample_nodes)

        edges = [
            GraphEdge(
                source_id=sample_nodes[0].entity_id,
                target_id=sample_nodes[1].entity_id,
                relationship_type=ExtendedRelationshipType.RESOLVES_TO,
            ),
            GraphEdge(
                source_id=sample_nodes[2].entity_id,
                target_id=sample_nodes[0].entity_id,
                relationship_type=ExtendedRelationshipType.ATTRIBUTED_TO,
            ),
        ]
        client.batch_create_edges(edges)

        stats = client.get_statistics()

        assert stats.total_nodes == 4
        assert stats.total_edges == 2
        assert stats.nodes_by_type["domain"] == 1
        assert stats.nodes_by_type["ip_address"] == 1
        assert stats.nodes_by_type["threat_actor"] == 1
        assert stats.average_degree == 1.0  # 4 edges / 4 nodes


class TestQueryExecution:
    """Tests for raw query execution."""

    def test_execute_cypher_mock(self, client):
        """Test Cypher execution in mock mode."""
        result = client.execute_cypher("MATCH (n) RETURN n LIMIT 10")

        assert result.success is True
        assert result.query == "MATCH (n) RETURN n LIMIT 10"
        assert result.error is None


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_node_with_special_characters(self, client):
        """Test node with special characters in value."""
        node = GraphNode(
            value="test@domain.com's \"special\" <chars>",
            entity_type=ExtendedEntityType.EMAIL,
        )

        created = client.create_node(node)
        retrieved = client.get_node(node.entity_id)

        assert retrieved is not None
        assert "special" in retrieved.value

    def test_delete_node_removes_edges(self, client, sample_nodes):
        """Test that deleting a node removes connected edges."""
        client.batch_create_nodes(sample_nodes[:2])

        edge = GraphEdge(
            source_id=sample_nodes[0].entity_id,
            target_id=sample_nodes[1].entity_id,
            relationship_type=ExtendedRelationshipType.RESOLVES_TO,
        )
        client.create_edge(edge)

        # Delete source node
        client.delete_node(sample_nodes[0].entity_id)

        # Edge should be gone
        result = client.get_edge(sample_nodes[0].entity_id, sample_nodes[1].entity_id)
        assert result is None

    def test_large_batch(self, client):
        """Test handling of large batches."""
        # Create 1000 nodes
        nodes = [
            GraphNode(
                value=f"node-{i}.com",
                entity_type=ExtendedEntityType.DOMAIN,
            )
            for i in range(1000)
        ]

        created = client.batch_create_nodes(nodes, batch_size=100)
        assert created == 1000

        stats = client.get_statistics()
        assert stats.total_nodes == 1000
