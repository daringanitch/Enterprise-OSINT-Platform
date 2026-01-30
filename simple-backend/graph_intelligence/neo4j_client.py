#!/usr/bin/env python3
"""
Neo4j Graph Database Client

Provides connection management, CRUD operations, and query execution
for the Graph Intelligence Engine.

Supports:
- Connection pooling and health checks
- Node and edge CRUD operations
- Batch operations for bulk imports
- Query execution with parameter binding
- Transaction support
- Index management
"""

import logging
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple, Union

from .models import (
    ExtendedEntityType,
    ExtendedRelationshipType,
    GraphNode,
    GraphEdge,
    GraphStatistics,
    GraphConfig,
    QueryResult,
)

logger = logging.getLogger(__name__)


# =============================================================================
# NEO4J DRIVER ABSTRACTION
# =============================================================================

class Neo4jDriver:
    """
    Wrapper around neo4j driver for abstraction and testing.
    Falls back to mock implementation if neo4j package not available.
    """

    def __init__(self, uri: str, username: str, password: str, database: str = "neo4j"):
        self.uri = uri
        self.username = username
        self.password = password
        self.database = database
        self._driver = None
        self._connected = False
        self._mock_mode = False

        self._connect()

    def _connect(self):
        """Establish connection to Neo4j."""
        try:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(
                self.uri,
                auth=(self.username, self.password),
                max_connection_lifetime=3600,
                max_connection_pool_size=50,
                connection_acquisition_timeout=60,
            )
            # Verify connectivity
            self._driver.verify_connectivity()
            self._connected = True
            logger.info(f"Connected to Neo4j at {self.uri}")
        except ImportError:
            logger.warning("neo4j package not installed, using mock mode")
            self._mock_mode = True
            self._connected = True
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            self._mock_mode = True
            self._connected = True
            logger.warning("Falling back to mock mode")

    def close(self):
        """Close the driver connection."""
        if self._driver:
            self._driver.close()
            self._connected = False
            logger.info("Neo4j connection closed")

    @property
    def is_connected(self) -> bool:
        """Check if connected to Neo4j."""
        return self._connected

    @property
    def is_mock_mode(self) -> bool:
        """Check if running in mock mode."""
        return self._mock_mode

    def session(self, database: str = None):
        """Get a database session."""
        if self._mock_mode:
            return MockSession()
        return self._driver.session(database=database or self.database)

    def execute_query(
        self,
        query: str,
        parameters: Dict[str, Any] = None,
        database: str = None
    ) -> Tuple[List[Dict], Any, Any]:
        """Execute a Cypher query and return results."""
        if self._mock_mode:
            return self._mock_execute(query, parameters)

        with self.session(database) as session:
            result = session.run(query, parameters or {})
            records = [dict(record) for record in result]
            summary = result.consume()
            return records, summary, None

    def _mock_execute(
        self,
        query: str,
        parameters: Dict[str, Any] = None
    ) -> Tuple[List[Dict], Any, Any]:
        """Mock query execution for testing."""
        logger.debug(f"Mock executing: {query[:100]}...")
        # Return empty results for mock mode
        return [], None, None


class MockSession:
    """Mock session for testing without Neo4j."""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def run(self, query: str, parameters: Dict = None):
        return MockResult()

    def begin_transaction(self):
        return MockTransaction()


class MockResult:
    """Mock result for testing."""

    def __iter__(self):
        return iter([])

    def consume(self):
        return None

    def single(self):
        return None


class MockTransaction:
    """Mock transaction for testing."""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def run(self, query: str, parameters: Dict = None):
        return MockResult()

    def commit(self):
        pass

    def rollback(self):
        pass


# =============================================================================
# GRAPH CLIENT
# =============================================================================

class GraphClient:
    """
    High-level Neo4j client for graph intelligence operations.

    Provides:
    - Node CRUD (create, read, update, delete)
    - Edge CRUD
    - Batch operations
    - Query execution
    - Index management
    - Statistics
    """

    # Neo4j labels for entity types
    ENTITY_LABEL_PREFIX = "Entity"

    def __init__(self, config: GraphConfig = None):
        """
        Initialize the graph client.

        Args:
            config: GraphConfig with connection settings
        """
        self.config = config or GraphConfig()
        self.driver = Neo4jDriver(
            uri=self.config.neo4j_uri,
            username=self.config.neo4j_username,
            password=self.config.neo4j_password,
            database=self.config.neo4j_database,
        )

        # In-memory cache for mock mode
        self._mock_nodes: Dict[str, GraphNode] = {}
        self._mock_edges: Dict[str, GraphEdge] = {}

        # Initialize schema if connected
        if self.driver.is_connected and not self.driver.is_mock_mode:
            self._ensure_schema()

    def close(self):
        """Close the client connection."""
        self.driver.close()

    @property
    def is_connected(self) -> bool:
        """Check if connected to database."""
        return self.driver.is_connected

    @property
    def is_mock_mode(self) -> bool:
        """Check if running in mock mode."""
        return self.driver.is_mock_mode

    # =========================================================================
    # SCHEMA MANAGEMENT
    # =========================================================================

    def _ensure_schema(self):
        """Create indexes and constraints if they don't exist."""
        try:
            self._create_indexes()
            self._create_constraints()
            logger.info("Neo4j schema initialized")
        except Exception as e:
            logger.error(f"Failed to initialize schema: {e}")

    def _create_indexes(self):
        """Create indexes for efficient queries."""
        indexes = [
            # Entity indexes
            "CREATE INDEX entity_id_idx IF NOT EXISTS FOR (n:Entity) ON (n.entity_id)",
            "CREATE INDEX entity_type_idx IF NOT EXISTS FOR (n:Entity) ON (n.entity_type)",
            "CREATE INDEX entity_value_idx IF NOT EXISTS FOR (n:Entity) ON (n.normalized_value)",
            "CREATE INDEX entity_risk_idx IF NOT EXISTS FOR (n:Entity) ON (n.risk_score)",
            "CREATE INDEX entity_confidence_idx IF NOT EXISTS FOR (n:Entity) ON (n.confidence)",

            # Temporal indexes
            "CREATE INDEX entity_created_idx IF NOT EXISTS FOR (n:Entity) ON (n.created_at)",
            "CREATE INDEX entity_updated_idx IF NOT EXISTS FOR (n:Entity) ON (n.updated_at)",

            # Investigation index
            "CREATE INDEX entity_investigation_idx IF NOT EXISTS FOR (n:Entity) ON (n.investigation_ids)",

            # Community index
            "CREATE INDEX entity_community_idx IF NOT EXISTS FOR (n:Entity) ON (n.community_id)",
        ]

        for index_query in indexes:
            try:
                self.driver.execute_query(index_query)
            except Exception as e:
                logger.debug(f"Index creation note: {e}")

    def _create_constraints(self):
        """Create uniqueness constraints."""
        constraints = [
            "CREATE CONSTRAINT entity_id_unique IF NOT EXISTS FOR (n:Entity) REQUIRE n.entity_id IS UNIQUE",
            "CREATE CONSTRAINT node_id_unique IF NOT EXISTS FOR (n:Entity) REQUIRE n.node_id IS UNIQUE",
        ]

        for constraint_query in constraints:
            try:
                self.driver.execute_query(constraint_query)
            except Exception as e:
                logger.debug(f"Constraint creation note: {e}")

    # =========================================================================
    # NODE OPERATIONS
    # =========================================================================

    def create_node(self, node: GraphNode) -> GraphNode:
        """
        Create a new node in the graph.

        Args:
            node: GraphNode to create

        Returns:
            Created GraphNode with updated metadata
        """
        if self.driver.is_mock_mode:
            self._mock_nodes[node.entity_id] = node
            logger.debug(f"Mock created node: {node.entity_id}")
            return node

        # Build Cypher query
        labels = self._get_node_labels(node)
        properties = node.to_neo4j_properties()

        query = f"""
        CREATE (n:{':'.join(labels)})
        SET n = $props
        RETURN n
        """

        try:
            records, _, _ = self.driver.execute_query(query, {"props": properties})
            logger.info(f"Created node: {node.entity_id} ({node.entity_type.value})")
            return node
        except Exception as e:
            logger.error(f"Failed to create node {node.entity_id}: {e}")
            raise

    def get_node(self, entity_id: str) -> Optional[GraphNode]:
        """
        Get a node by entity ID.

        Args:
            entity_id: The entity ID to look up

        Returns:
            GraphNode if found, None otherwise
        """
        if self.driver.is_mock_mode:
            return self._mock_nodes.get(entity_id)

        query = """
        MATCH (n:Entity {entity_id: $entity_id})
        RETURN n
        """

        try:
            records, _, _ = self.driver.execute_query(query, {"entity_id": entity_id})
            if records:
                return self._record_to_node(records[0]["n"])
            return None
        except Exception as e:
            logger.error(f"Failed to get node {entity_id}: {e}")
            return None

    def get_nodes_by_type(
        self,
        entity_type: ExtendedEntityType,
        limit: int = 100,
        offset: int = 0
    ) -> List[GraphNode]:
        """
        Get nodes by entity type.

        Args:
            entity_type: Type of entities to retrieve
            limit: Maximum number of nodes to return
            offset: Number of nodes to skip

        Returns:
            List of GraphNode objects
        """
        if self.driver.is_mock_mode:
            nodes = [n for n in self._mock_nodes.values()
                    if n.entity_type == entity_type]
            return nodes[offset:offset + limit]

        query = """
        MATCH (n:Entity {entity_type: $type})
        RETURN n
        ORDER BY n.created_at DESC
        SKIP $offset
        LIMIT $limit
        """

        try:
            records, _, _ = self.driver.execute_query(
                query,
                {"type": entity_type.value, "limit": limit, "offset": offset}
            )
            return [self._record_to_node(r["n"]) for r in records]
        except Exception as e:
            logger.error(f"Failed to get nodes by type {entity_type}: {e}")
            return []

    def get_nodes_by_investigation(self, investigation_id: str) -> List[GraphNode]:
        """
        Get all nodes linked to an investigation.

        Args:
            investigation_id: Investigation ID

        Returns:
            List of GraphNode objects
        """
        if self.driver.is_mock_mode:
            return [n for n in self._mock_nodes.values()
                   if investigation_id in n.investigation_ids]

        query = """
        MATCH (n:Entity)
        WHERE $inv_id IN n.investigation_ids
        RETURN n
        ORDER BY n.created_at
        """

        try:
            records, _, _ = self.driver.execute_query(
                query,
                {"inv_id": investigation_id}
            )
            return [self._record_to_node(r["n"]) for r in records]
        except Exception as e:
            logger.error(f"Failed to get nodes for investigation {investigation_id}: {e}")
            return []

    def update_node(self, node: GraphNode) -> GraphNode:
        """
        Update an existing node.

        Args:
            node: GraphNode with updated data

        Returns:
            Updated GraphNode
        """
        node.updated_at = datetime.utcnow()
        node.version += 1

        if self.driver.is_mock_mode:
            self._mock_nodes[node.entity_id] = node
            return node

        properties = node.to_neo4j_properties()

        query = """
        MATCH (n:Entity {entity_id: $entity_id})
        SET n = $props
        RETURN n
        """

        try:
            records, _, _ = self.driver.execute_query(
                query,
                {"entity_id": node.entity_id, "props": properties}
            )
            logger.info(f"Updated node: {node.entity_id}")
            return node
        except Exception as e:
            logger.error(f"Failed to update node {node.entity_id}: {e}")
            raise

    def upsert_node(self, node: GraphNode) -> GraphNode:
        """
        Create or update a node (merge operation).

        Args:
            node: GraphNode to upsert

        Returns:
            Upserted GraphNode
        """
        existing = self.get_node(node.entity_id)
        if existing:
            existing.merge_from(node)
            return self.update_node(existing)
        return self.create_node(node)

    def delete_node(self, entity_id: str) -> bool:
        """
        Delete a node and its relationships.

        Args:
            entity_id: Entity ID to delete

        Returns:
            True if deleted, False otherwise
        """
        if self.driver.is_mock_mode:
            if entity_id in self._mock_nodes:
                del self._mock_nodes[entity_id]
                # Remove related edges
                self._mock_edges = {
                    k: v for k, v in self._mock_edges.items()
                    if v.source_id != entity_id and v.target_id != entity_id
                }
                return True
            return False

        query = """
        MATCH (n:Entity {entity_id: $entity_id})
        DETACH DELETE n
        RETURN count(n) as deleted
        """

        try:
            records, _, _ = self.driver.execute_query(query, {"entity_id": entity_id})
            deleted = records[0]["deleted"] if records else 0
            if deleted > 0:
                logger.info(f"Deleted node: {entity_id}")
            return deleted > 0
        except Exception as e:
            logger.error(f"Failed to delete node {entity_id}: {e}")
            return False

    def search_nodes(
        self,
        value: str,
        entity_type: ExtendedEntityType = None,
        limit: int = 50
    ) -> List[GraphNode]:
        """
        Search nodes by value (case-insensitive).

        Args:
            value: Search term
            entity_type: Optional type filter
            limit: Maximum results

        Returns:
            List of matching GraphNode objects
        """
        if self.driver.is_mock_mode:
            value_lower = value.lower()
            results = []
            for node in self._mock_nodes.values():
                if value_lower in node.value.lower() or value_lower in node.normalized_value:
                    if entity_type is None or node.entity_type == entity_type:
                        results.append(node)
                        if len(results) >= limit:
                            break
            return results

        type_filter = ""
        params = {"search": f"(?i).*{value}.*", "limit": limit}

        if entity_type:
            type_filter = "AND n.entity_type = $type"
            params["type"] = entity_type.value

        query = f"""
        MATCH (n:Entity)
        WHERE n.value =~ $search OR n.normalized_value =~ $search
        {type_filter}
        RETURN n
        LIMIT $limit
        """

        try:
            records, _, _ = self.driver.execute_query(query, params)
            return [self._record_to_node(r["n"]) for r in records]
        except Exception as e:
            logger.error(f"Failed to search nodes for '{value}': {e}")
            return []

    # =========================================================================
    # EDGE OPERATIONS
    # =========================================================================

    def create_edge(self, edge: GraphEdge) -> GraphEdge:
        """
        Create a relationship between two nodes.

        Args:
            edge: GraphEdge to create

        Returns:
            Created GraphEdge
        """
        if self.driver.is_mock_mode:
            self._mock_edges[edge.edge_id] = edge
            logger.debug(f"Mock created edge: {edge.edge_id}")
            return edge

        rel_type = edge.relationship_type.value.upper()
        properties = edge.to_neo4j_properties()

        query = f"""
        MATCH (source:Entity {{entity_id: $source_id}})
        MATCH (target:Entity {{entity_id: $target_id}})
        CREATE (source)-[r:{rel_type}]->(target)
        SET r = $props
        RETURN r
        """

        try:
            records, _, _ = self.driver.execute_query(
                query,
                {
                    "source_id": edge.source_id,
                    "target_id": edge.target_id,
                    "props": properties
                }
            )
            logger.info(f"Created edge: {edge.source_id} -[{rel_type}]-> {edge.target_id}")
            return edge
        except Exception as e:
            logger.error(f"Failed to create edge {edge.edge_id}: {e}")
            raise

    def get_edge(
        self,
        source_id: str,
        target_id: str,
        relationship_type: ExtendedRelationshipType = None
    ) -> Optional[GraphEdge]:
        """
        Get an edge between two nodes.

        Args:
            source_id: Source node entity ID
            target_id: Target node entity ID
            relationship_type: Optional relationship type filter

        Returns:
            GraphEdge if found, None otherwise
        """
        if self.driver.is_mock_mode:
            for edge in self._mock_edges.values():
                if edge.source_id == source_id and edge.target_id == target_id:
                    if relationship_type is None or edge.relationship_type == relationship_type:
                        return edge
            return None

        type_clause = ""
        params = {"source_id": source_id, "target_id": target_id}

        if relationship_type:
            type_clause = f":{relationship_type.value.upper()}"

        query = f"""
        MATCH (source:Entity {{entity_id: $source_id}})
              -[r{type_clause}]->
              (target:Entity {{entity_id: $target_id}})
        RETURN r, type(r) as rel_type
        """

        try:
            records, _, _ = self.driver.execute_query(query, params)
            if records:
                return self._record_to_edge(records[0]["r"], records[0]["rel_type"])
            return None
        except Exception as e:
            logger.error(f"Failed to get edge {source_id} -> {target_id}: {e}")
            return None

    def get_edges_for_node(
        self,
        entity_id: str,
        direction: str = "both"
    ) -> List[GraphEdge]:
        """
        Get all edges connected to a node.

        Args:
            entity_id: Node entity ID
            direction: "in", "out", or "both"

        Returns:
            List of GraphEdge objects
        """
        if self.driver.is_mock_mode:
            edges = []
            for edge in self._mock_edges.values():
                if direction in ("both", "out") and edge.source_id == entity_id:
                    edges.append(edge)
                elif direction in ("both", "in") and edge.target_id == entity_id:
                    edges.append(edge)
            return edges

        if direction == "out":
            query = """
            MATCH (n:Entity {entity_id: $entity_id})-[r]->(m)
            RETURN r, type(r) as rel_type, n.entity_id as source, m.entity_id as target
            """
        elif direction == "in":
            query = """
            MATCH (n:Entity {entity_id: $entity_id})<-[r]-(m)
            RETURN r, type(r) as rel_type, m.entity_id as source, n.entity_id as target
            """
        else:
            query = """
            MATCH (n:Entity {entity_id: $entity_id})-[r]-(m)
            RETURN r, type(r) as rel_type,
                   CASE WHEN startNode(r) = n THEN n.entity_id ELSE m.entity_id END as source,
                   CASE WHEN endNode(r) = n THEN n.entity_id ELSE m.entity_id END as target
            """

        try:
            records, _, _ = self.driver.execute_query(query, {"entity_id": entity_id})
            return [
                self._record_to_edge(r["r"], r["rel_type"], r["source"], r["target"])
                for r in records
            ]
        except Exception as e:
            logger.error(f"Failed to get edges for node {entity_id}: {e}")
            return []

    def update_edge(self, edge: GraphEdge) -> GraphEdge:
        """
        Update an existing edge.

        Args:
            edge: GraphEdge with updated data

        Returns:
            Updated GraphEdge
        """
        edge.updated_at = datetime.utcnow()
        edge.version += 1

        if self.driver.is_mock_mode:
            self._mock_edges[edge.edge_id] = edge
            return edge

        rel_type = edge.relationship_type.value.upper()
        properties = edge.to_neo4j_properties()

        query = f"""
        MATCH (source:Entity {{entity_id: $source_id}})
              -[r:{rel_type}]->
              (target:Entity {{entity_id: $target_id}})
        SET r = $props
        RETURN r
        """

        try:
            records, _, _ = self.driver.execute_query(
                query,
                {
                    "source_id": edge.source_id,
                    "target_id": edge.target_id,
                    "props": properties
                }
            )
            logger.info(f"Updated edge: {edge.edge_id}")
            return edge
        except Exception as e:
            logger.error(f"Failed to update edge {edge.edge_id}: {e}")
            raise

    def upsert_edge(self, edge: GraphEdge) -> GraphEdge:
        """
        Create or update an edge (merge operation).

        Args:
            edge: GraphEdge to upsert

        Returns:
            Upserted GraphEdge
        """
        existing = self.get_edge(edge.source_id, edge.target_id, edge.relationship_type)
        if existing:
            existing.merge_from(edge)
            return self.update_edge(existing)
        return self.create_edge(edge)

    def delete_edge(
        self,
        source_id: str,
        target_id: str,
        relationship_type: ExtendedRelationshipType = None
    ) -> bool:
        """
        Delete an edge between two nodes.

        Args:
            source_id: Source node entity ID
            target_id: Target node entity ID
            relationship_type: Optional relationship type

        Returns:
            True if deleted, False otherwise
        """
        if self.driver.is_mock_mode:
            to_delete = []
            for edge_id, edge in self._mock_edges.items():
                if edge.source_id == source_id and edge.target_id == target_id:
                    if relationship_type is None or edge.relationship_type == relationship_type:
                        to_delete.append(edge_id)
            for edge_id in to_delete:
                del self._mock_edges[edge_id]
            return len(to_delete) > 0

        type_clause = ""
        if relationship_type:
            type_clause = f":{relationship_type.value.upper()}"

        query = f"""
        MATCH (source:Entity {{entity_id: $source_id}})
              -[r{type_clause}]->
              (target:Entity {{entity_id: $target_id}})
        DELETE r
        RETURN count(r) as deleted
        """

        try:
            records, _, _ = self.driver.execute_query(
                query,
                {"source_id": source_id, "target_id": target_id}
            )
            deleted = records[0]["deleted"] if records else 0
            if deleted > 0:
                logger.info(f"Deleted edge: {source_id} -> {target_id}")
            return deleted > 0
        except Exception as e:
            logger.error(f"Failed to delete edge {source_id} -> {target_id}: {e}")
            return False

    # =========================================================================
    # BATCH OPERATIONS
    # =========================================================================

    def batch_create_nodes(
        self,
        nodes: List[GraphNode],
        batch_size: int = 500
    ) -> int:
        """
        Create multiple nodes in batches.

        Args:
            nodes: List of GraphNode objects
            batch_size: Number of nodes per batch

        Returns:
            Number of nodes created
        """
        if self.driver.is_mock_mode:
            for node in nodes:
                self._mock_nodes[node.entity_id] = node
            return len(nodes)

        created = 0
        for i in range(0, len(nodes), batch_size):
            batch = nodes[i:i + batch_size]
            props_list = [n.to_neo4j_properties() for n in batch]

            query = """
            UNWIND $nodes as node
            CREATE (n:Entity)
            SET n = node
            RETURN count(n) as created
            """

            try:
                records, _, _ = self.driver.execute_query(query, {"nodes": props_list})
                batch_created = records[0]["created"] if records else 0
                created += batch_created
                logger.debug(f"Created batch of {batch_created} nodes")
            except Exception as e:
                logger.error(f"Failed to create node batch: {e}")

        logger.info(f"Batch created {created} nodes")
        return created

    def batch_create_edges(
        self,
        edges: List[GraphEdge],
        batch_size: int = 500
    ) -> int:
        """
        Create multiple edges in batches.

        Args:
            edges: List of GraphEdge objects
            batch_size: Number of edges per batch

        Returns:
            Number of edges created
        """
        if self.driver.is_mock_mode:
            for edge in edges:
                self._mock_edges[edge.edge_id] = edge
            return len(edges)

        created = 0

        # Group edges by relationship type for efficient batch creation
        edges_by_type: Dict[str, List[GraphEdge]] = {}
        for edge in edges:
            rel_type = edge.relationship_type.value.upper()
            if rel_type not in edges_by_type:
                edges_by_type[rel_type] = []
            edges_by_type[rel_type].append(edge)

        for rel_type, type_edges in edges_by_type.items():
            for i in range(0, len(type_edges), batch_size):
                batch = type_edges[i:i + batch_size]
                edge_data = [
                    {
                        "source_id": e.source_id,
                        "target_id": e.target_id,
                        "props": e.to_neo4j_properties()
                    }
                    for e in batch
                ]

                query = f"""
                UNWIND $edges as edge
                MATCH (source:Entity {{entity_id: edge.source_id}})
                MATCH (target:Entity {{entity_id: edge.target_id}})
                CREATE (source)-[r:{rel_type}]->(target)
                SET r = edge.props
                RETURN count(r) as created
                """

                try:
                    records, _, _ = self.driver.execute_query(query, {"edges": edge_data})
                    batch_created = records[0]["created"] if records else 0
                    created += batch_created
                except Exception as e:
                    logger.error(f"Failed to create edge batch: {e}")

        logger.info(f"Batch created {created} edges")
        return created

    def batch_upsert_nodes(
        self,
        nodes: List[GraphNode],
        batch_size: int = 500
    ) -> int:
        """
        Upsert multiple nodes in batches.

        Args:
            nodes: List of GraphNode objects
            batch_size: Number of nodes per batch

        Returns:
            Number of nodes upserted
        """
        if self.driver.is_mock_mode:
            for node in nodes:
                existing = self._mock_nodes.get(node.entity_id)
                if existing:
                    existing.merge_from(node)
                else:
                    self._mock_nodes[node.entity_id] = node
            return len(nodes)

        upserted = 0
        for i in range(0, len(nodes), batch_size):
            batch = nodes[i:i + batch_size]
            props_list = [n.to_neo4j_properties() for n in batch]

            query = """
            UNWIND $nodes as node
            MERGE (n:Entity {entity_id: node.entity_id})
            ON CREATE SET n = node
            ON MATCH SET
                n.sources = CASE WHEN n.sources IS NULL THEN node.sources
                            ELSE n.sources + [s IN node.sources WHERE NOT s IN n.sources] END,
                n.confidence = CASE WHEN node.confidence > n.confidence THEN node.confidence ELSE n.confidence END,
                n.updated_at = node.updated_at,
                n.version = n.version + 1
            RETURN count(n) as upserted
            """

            try:
                records, _, _ = self.driver.execute_query(query, {"nodes": props_list})
                batch_upserted = records[0]["upserted"] if records else 0
                upserted += batch_upserted
            except Exception as e:
                logger.error(f"Failed to upsert node batch: {e}")

        logger.info(f"Batch upserted {upserted} nodes")
        return upserted

    # =========================================================================
    # NEIGHBOR QUERIES
    # =========================================================================

    def get_neighbors(
        self,
        entity_id: str,
        depth: int = 1,
        relationship_types: List[ExtendedRelationshipType] = None,
        entity_types: List[ExtendedEntityType] = None,
        limit: int = 100
    ) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """
        Get neighboring nodes and connecting edges.

        Args:
            entity_id: Starting node entity ID
            depth: How many hops to traverse (1-3)
            relationship_types: Filter by relationship types
            entity_types: Filter by entity types
            limit: Maximum nodes to return

        Returns:
            Tuple of (nodes, edges)
        """
        depth = min(max(1, depth), 3)  # Clamp between 1 and 3

        if self.driver.is_mock_mode:
            return self._mock_get_neighbors(
                entity_id, depth, relationship_types, entity_types, limit
            )

        # Build relationship type filter
        rel_filter = ""
        if relationship_types:
            rel_types = "|".join([rt.value.upper() for rt in relationship_types])
            rel_filter = f":{rel_types}"

        # Build entity type filter
        type_filter = ""
        if entity_types:
            types = [et.value for et in entity_types]
            type_filter = "AND m.entity_type IN $entity_types"

        query = f"""
        MATCH path = (n:Entity {{entity_id: $entity_id}})-[r{rel_filter}*1..{depth}]-(m:Entity)
        WHERE n <> m {type_filter}
        WITH DISTINCT m, r
        LIMIT $limit
        RETURN m, r
        """

        params = {"entity_id": entity_id, "limit": limit}
        if entity_types:
            params["entity_types"] = [et.value for et in entity_types]

        try:
            records, _, _ = self.driver.execute_query(query, params)

            nodes = []
            edges = []
            seen_nodes = set()
            seen_edges = set()

            for record in records:
                # Get node
                node = self._record_to_node(record["m"])
                if node.entity_id not in seen_nodes:
                    nodes.append(node)
                    seen_nodes.add(node.entity_id)

                # Get edges from path
                for rel in record["r"]:
                    edge_key = (rel.start_node["entity_id"], rel.end_node["entity_id"], rel.type)
                    if edge_key not in seen_edges:
                        edge = self._record_to_edge(rel, rel.type)
                        edges.append(edge)
                        seen_edges.add(edge_key)

            return nodes, edges
        except Exception as e:
            logger.error(f"Failed to get neighbors for {entity_id}: {e}")
            return [], []

    def _mock_get_neighbors(
        self,
        entity_id: str,
        depth: int,
        relationship_types: List[ExtendedRelationshipType],
        entity_types: List[ExtendedEntityType],
        limit: int
    ) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """Mock implementation of neighbor query."""
        nodes = []
        edges = []
        visited = {entity_id}
        current_level = {entity_id}

        for _ in range(depth):
            next_level = set()
            for node_id in current_level:
                for edge in self._mock_edges.values():
                    neighbor_id = None
                    if edge.source_id == node_id:
                        neighbor_id = edge.target_id
                    elif edge.target_id == node_id:
                        neighbor_id = edge.source_id

                    if neighbor_id and neighbor_id not in visited:
                        # Apply filters
                        if relationship_types and edge.relationship_type not in relationship_types:
                            continue

                        neighbor = self._mock_nodes.get(neighbor_id)
                        if neighbor:
                            if entity_types and neighbor.entity_type not in entity_types:
                                continue

                            nodes.append(neighbor)
                            edges.append(edge)
                            visited.add(neighbor_id)
                            next_level.add(neighbor_id)

                            if len(nodes) >= limit:
                                return nodes[:limit], edges

            current_level = next_level

        return nodes[:limit], edges

    # =========================================================================
    # STATISTICS
    # =========================================================================

    def get_statistics(self) -> GraphStatistics:
        """
        Get graph statistics.

        Returns:
            GraphStatistics object
        """
        if self.driver.is_mock_mode:
            return self._mock_get_statistics()

        stats = GraphStatistics()

        # Get node and edge counts
        count_query = """
        MATCH (n:Entity)
        OPTIONAL MATCH (n)-[r]-()
        RETURN count(DISTINCT n) as node_count, count(DISTINCT r) as edge_count
        """

        try:
            records, _, _ = self.driver.execute_query(count_query)
            if records:
                stats.total_nodes = records[0]["node_count"]
                stats.total_edges = records[0]["edge_count"]
        except Exception as e:
            logger.error(f"Failed to get counts: {e}")

        # Get nodes by type
        type_query = """
        MATCH (n:Entity)
        RETURN n.entity_type as type, count(n) as count
        """

        try:
            records, _, _ = self.driver.execute_query(type_query)
            stats.nodes_by_type = {r["type"]: r["count"] for r in records}
        except Exception as e:
            logger.error(f"Failed to get node types: {e}")

        # Get edges by type
        rel_query = """
        MATCH ()-[r]->()
        RETURN type(r) as type, count(r) as count
        """

        try:
            records, _, _ = self.driver.execute_query(rel_query)
            stats.edges_by_type = {r["type"].lower(): r["count"] for r in records}
        except Exception as e:
            logger.error(f"Failed to get edge types: {e}")

        # Calculate density
        if stats.total_nodes > 1:
            max_edges = stats.total_nodes * (stats.total_nodes - 1)
            stats.density = stats.total_edges / max_edges if max_edges > 0 else 0

        # Average degree
        if stats.total_nodes > 0:
            stats.average_degree = (2 * stats.total_edges) / stats.total_nodes

        stats.computed_at = datetime.utcnow()
        return stats

    def _mock_get_statistics(self) -> GraphStatistics:
        """Get statistics for mock mode."""
        stats = GraphStatistics()
        stats.total_nodes = len(self._mock_nodes)
        stats.total_edges = len(self._mock_edges)

        # Nodes by type
        for node in self._mock_nodes.values():
            type_str = node.entity_type.value
            stats.nodes_by_type[type_str] = stats.nodes_by_type.get(type_str, 0) + 1

        # Edges by type
        for edge in self._mock_edges.values():
            type_str = edge.relationship_type.value
            stats.edges_by_type[type_str] = stats.edges_by_type.get(type_str, 0) + 1

        # Calculate density
        if stats.total_nodes > 1:
            max_edges = stats.total_nodes * (stats.total_nodes - 1)
            stats.density = stats.total_edges / max_edges if max_edges > 0 else 0

        # Average degree
        if stats.total_nodes > 0:
            stats.average_degree = (2 * stats.total_edges) / stats.total_nodes

        stats.computed_at = datetime.utcnow()
        return stats

    # =========================================================================
    # QUERY EXECUTION
    # =========================================================================

    def execute_cypher(
        self,
        query: str,
        parameters: Dict[str, Any] = None
    ) -> QueryResult:
        """
        Execute a raw Cypher query.

        Args:
            query: Cypher query string
            parameters: Query parameters

        Returns:
            QueryResult with results
        """
        start_time = time.time()

        if self.driver.is_mock_mode:
            return QueryResult(
                success=True,
                query=query,
                nodes=[],
                edges=[],
                execution_time_ms=0.0,
            )

        try:
            records, summary, _ = self.driver.execute_query(query, parameters)
            execution_time = (time.time() - start_time) * 1000

            # Parse results
            nodes = []
            edges = []

            for record in records:
                for key, value in record.items():
                    if hasattr(value, "labels"):  # It's a node
                        nodes.append(dict(value))
                    elif hasattr(value, "type"):  # It's a relationship
                        edges.append({
                            "type": value.type,
                            "properties": dict(value)
                        })

            return QueryResult(
                success=True,
                query=query,
                nodes=nodes,
                edges=edges,
                total_nodes=len(nodes),
                total_edges=len(edges),
                execution_time_ms=execution_time,
            )
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            logger.error(f"Query execution failed: {e}")
            return QueryResult(
                success=False,
                query=query,
                error=str(e),
                execution_time_ms=execution_time,
            )

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    def _get_node_labels(self, node: GraphNode) -> List[str]:
        """Get Neo4j labels for a node."""
        labels = ["Entity"]
        # Add entity type as label (e.g., Domain, IpAddress)
        type_label = "".join(word.capitalize() for word in node.entity_type.value.split("_"))
        labels.append(type_label)
        return labels

    def _record_to_node(self, record: Any) -> GraphNode:
        """Convert Neo4j record to GraphNode."""
        if isinstance(record, dict):
            props = record
        else:
            props = dict(record)

        entity_type = ExtendedEntityType.from_string(props.get("entity_type", "organization"))

        node = GraphNode(
            node_id=props.get("node_id", ""),
            entity_id=props.get("entity_id", ""),
            entity_type=entity_type,
            value=props.get("value", ""),
            normalized_value=props.get("normalized_value", ""),
            label=props.get("label", ""),
            sources=props.get("sources", []),
            confidence=props.get("confidence", 0.5),
            in_degree=props.get("in_degree", 0),
            out_degree=props.get("out_degree", 0),
            degree_centrality=props.get("degree_centrality", 0.0),
            betweenness_centrality=props.get("betweenness_centrality", 0.0),
            closeness_centrality=props.get("closeness_centrality", 0.0),
            eigenvector_centrality=props.get("eigenvector_centrality", 0.0),
            pagerank=props.get("pagerank", 0.0),
            community_id=props.get("community_id"),
            community_role=props.get("community_role", "member"),
            risk_score=props.get("risk_score", 0.0),
            threat_level=props.get("threat_level", "unknown"),
            tags=props.get("tags", []),
            aliases=props.get("aliases", []),
            investigation_ids=props.get("investigation_ids", []),
            version=props.get("version", 1),
        )

        # Parse dates
        if props.get("first_seen"):
            try:
                node.first_seen = datetime.fromisoformat(props["first_seen"])
            except:
                pass

        if props.get("last_seen"):
            try:
                node.last_seen = datetime.fromisoformat(props["last_seen"])
            except:
                pass

        if props.get("created_at"):
            try:
                node.created_at = datetime.fromisoformat(props["created_at"])
            except:
                pass

        if props.get("updated_at"):
            try:
                node.updated_at = datetime.fromisoformat(props["updated_at"])
            except:
                pass

        return node

    def _record_to_edge(
        self,
        record: Any,
        rel_type: str,
        source_id: str = None,
        target_id: str = None
    ) -> GraphEdge:
        """Convert Neo4j record to GraphEdge."""
        if isinstance(record, dict):
            props = record
        else:
            props = dict(record)

        relationship_type = ExtendedRelationshipType.from_string(rel_type.lower())

        edge = GraphEdge(
            edge_id=props.get("edge_id", ""),
            source_id=source_id or props.get("source_id", ""),
            target_id=target_id or props.get("target_id", ""),
            relationship_type=relationship_type,
            weight=props.get("weight", 1.0),
            confidence=props.get("confidence", 0.5),
            sources=props.get("sources", []),
            active=props.get("active", True),
            bidirectional=props.get("bidirectional", False),
            investigation_ids=props.get("investigation_ids", []),
            version=props.get("version", 1),
        )

        # Parse dates
        if props.get("first_observed"):
            try:
                edge.first_observed = datetime.fromisoformat(props["first_observed"])
            except:
                pass

        if props.get("last_observed"):
            try:
                edge.last_observed = datetime.fromisoformat(props["last_observed"])
            except:
                pass

        return edge

    # =========================================================================
    # CONTEXT MANAGERS
    # =========================================================================

    @contextmanager
    def transaction(self) -> Generator:
        """
        Context manager for transactions.

        Usage:
            with client.transaction() as tx:
                tx.run("CREATE ...")
                tx.run("CREATE ...")
        """
        if self.driver.is_mock_mode:
            yield MockTransaction()
            return

        with self.driver.session() as session:
            tx = session.begin_transaction()
            try:
                yield tx
                tx.commit()
            except Exception as e:
                tx.rollback()
                raise


# =============================================================================
# FACTORY FUNCTION
# =============================================================================

def create_graph_client(
    uri: str = None,
    username: str = None,
    password: str = None,
    database: str = None
) -> GraphClient:
    """
    Create a GraphClient with the given configuration.

    Args:
        uri: Neo4j URI (default: bolt://localhost:7687)
        username: Neo4j username (default: neo4j)
        password: Neo4j password
        database: Neo4j database name

    Returns:
        Configured GraphClient instance
    """
    config = GraphConfig(
        neo4j_uri=uri or "bolt://localhost:7687",
        neo4j_username=username or "neo4j",
        neo4j_password=password or "",
        neo4j_database=database or "neo4j",
    )
    return GraphClient(config)
