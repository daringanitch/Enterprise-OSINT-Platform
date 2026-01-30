# Graph Intelligence Engine Architecture

## Executive Summary

This document defines the architecture for a Palantir-inspired Graph Intelligence Engine that transforms the existing entity correlation system into a persistent, queryable, algorithmically-rich knowledge graph for advanced OSINT analysis.

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           GRAPH INTELLIGENCE ENGINE                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────────────┐   │
│  │  Graph Query    │   │  Graph          │   │  Real-Time              │   │
│  │  Language (GQL) │   │  Algorithms     │   │  Stream Processor       │   │
│  │                 │   │                 │   │                         │   │
│  │  - Path queries │   │  - Centrality   │   │  - Entity changes       │   │
│  │  - Patterns     │   │  - Community    │   │  - Relationship updates │   │
│  │  - Aggregations │   │  - Similarity   │   │  - Alert triggers       │   │
│  └────────┬────────┘   └────────┬────────┘   └────────────┬────────────┘   │
│           │                     │                         │                 │
│           └─────────────────────┼─────────────────────────┘                 │
│                                 │                                           │
│                    ┌────────────▼────────────┐                              │
│                    │   Graph Service Layer   │                              │
│                    │                         │                              │
│                    │  - Entity CRUD          │                              │
│                    │  - Relationship Mgmt    │                              │
│                    │  - Transaction Support  │                              │
│                    │  - Cache Management     │                              │
│                    └────────────┬────────────┘                              │
│                                 │                                           │
│           ┌─────────────────────┼─────────────────────┐                     │
│           │                     │                     │                     │
│  ┌────────▼────────┐  ┌────────▼────────┐  ┌────────▼────────┐             │
│  │    Neo4j        │  │    Redis        │  │   PostgreSQL    │             │
│  │  (Primary)      │  │   (Cache)       │  │   (Metadata)    │             │
│  │                 │  │                 │  │                 │             │
│  │  - Nodes        │  │  - Hot paths    │  │  - Audit logs   │             │
│  │  - Edges        │  │  - Query cache  │  │  - User prefs   │             │
│  │  - Properties   │  │  - Sessions     │  │  - Job history  │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
           ┌────────▼───────┐ ┌────▼────┐ ┌───────▼────────┐
           │ Correlation    │ │   MCP   │ │  External      │
           │ Engine         │ │ Servers │ │  Data Feeds    │
           │ (Existing)     │ │         │ │  (STIX/TAXII)  │
           └────────────────┘ └─────────┘ └────────────────┘
```

---

## 2. Data Model

### 2.1 Node (Entity) Schema

```python
class GraphNode:
    """Persistent graph node representing an entity"""

    # Core identifiers
    node_id: str              # Unique graph ID (UUID)
    entity_id: str            # Correlation engine entity ID
    entity_type: EntityType   # DOMAIN, IP_ADDRESS, PERSON, etc.

    # Primary data
    value: str                # Primary display value
    normalized_value: str     # Normalized for matching
    label: str                # Human-readable label

    # Provenance
    sources: List[str]        # Intelligence sources
    confidence: float         # 0.0-1.0 confidence score
    first_seen: datetime      # First observation
    last_seen: datetime       # Most recent observation

    # Graph properties
    in_degree: int            # Incoming relationship count
    out_degree: int           # Outgoing relationship count
    betweenness: float        # Betweenness centrality score
    pagerank: float           # PageRank influence score
    community_id: str         # Detected community cluster

    # Extended attributes
    properties: Dict[str, Any]  # Entity-specific properties
    tags: List[str]             # Classification tags
    risk_score: float           # Computed risk (0-100)

    # Temporal
    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime]
```

### 2.2 Edge (Relationship) Schema

```python
class GraphEdge:
    """Persistent graph edge representing a relationship"""

    # Core identifiers
    edge_id: str              # Unique edge ID
    source_id: str            # Source node ID
    target_id: str            # Target node ID
    relationship_type: RelationshipType

    # Relationship strength
    weight: float             # Relationship strength (0.0-1.0)
    confidence: float         # Confidence score

    # Provenance
    sources: List[str]        # Intelligence sources
    evidence: List[Dict]      # Supporting evidence

    # Temporal
    first_observed: datetime
    last_observed: datetime
    active: bool              # Currently active relationship

    # Properties
    attributes: Dict[str, Any]
    bidirectional: bool       # Relationship goes both ways
```

### 2.3 Extended Entity Types

```python
class ExtendedEntityType(Enum):
    """Extended entity types for graph intelligence"""

    # Existing types
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    EMAIL = "email"
    PERSON = "person"
    ORGANIZATION = "organization"
    URL = "url"
    HASH = "hash"
    PHONE = "phone"
    SOCIAL_ACCOUNT = "social_account"
    CERTIFICATE = "certificate"
    ASN = "asn"
    TECHNOLOGY = "technology"

    # New types for advanced analysis
    LOCATION = "location"           # Geospatial entity
    CRYPTOCURRENCY_WALLET = "crypto_wallet"
    BANK_ACCOUNT = "bank_account"
    VEHICLE = "vehicle"
    DOCUMENT = "document"
    EVENT = "event"                 # Temporal event node
    CAMPAIGN = "campaign"           # Threat campaign
    THREAT_ACTOR = "threat_actor"
    MALWARE_FAMILY = "malware_family"
    VULNERABILITY = "vulnerability"  # CVE
    DEVICE = "device"               # IoT/hardware
    SOFTWARE = "software"
    NETWORK_SEGMENT = "network_segment"
    DATA_BREACH = "data_breach"
    LEGAL_ENTITY = "legal_entity"   # Corporate structure
```

### 2.4 Extended Relationship Types

```python
class ExtendedRelationshipType(Enum):
    """Extended relationship types for rich graph modeling"""

    # Existing types
    RESOLVES_TO = "resolves_to"
    OWNS = "owns"
    REGISTERED_BY = "registered_by"
    HOSTS = "hosts"
    ASSOCIATED_WITH = "associated_with"
    SUBDOMAIN_OF = "subdomain_of"
    USES_TECHNOLOGY = "uses_technology"
    ISSUED_FOR = "issued_for"
    MENTIONS = "mentions"
    EXPOSED_IN = "exposed_in"
    MEMBER_OF = "member_of"
    CONTROLS = "controls"

    # Infrastructure relationships
    ROUTES_THROUGH = "routes_through"
    PEERS_WITH = "peers_with"
    UPSTREAM_OF = "upstream_of"
    SHARES_INFRASTRUCTURE = "shares_infrastructure"
    COLOCATED_WITH = "colocated_with"

    # Threat relationships
    ATTRIBUTED_TO = "attributed_to"
    TARGETS = "targets"
    EXPLOITS = "exploits"
    DELIVERS = "delivers"
    COMMUNICATES_WITH = "communicates_with"  # C2
    DOWNLOADS_FROM = "downloads_from"
    SIMILAR_TO = "similar_to"
    VARIANT_OF = "variant_of"

    # Financial relationships
    TRANSACTS_WITH = "transacts_with"
    FUNDS = "funds"
    SUBSIDIARY_OF = "subsidiary_of"
    INVESTS_IN = "invests_in"

    # Person relationships
    WORKS_FOR = "works_for"
    KNOWS = "knows"
    RELATED_TO = "related_to"
    ALIASES = "aliases"
    IMPERSONATES = "impersonates"

    # Temporal relationships
    PRECEDED_BY = "preceded_by"
    FOLLOWED_BY = "followed_by"
    CONCURRENT_WITH = "concurrent_with"

    # Location relationships
    LOCATED_IN = "located_in"
    TRAVELED_TO = "traveled_to"
    OPERATES_IN = "operates_in"
```

---

## 3. Graph Algorithms

### 3.1 Centrality Algorithms

```python
class CentralityAlgorithms:
    """Identify important nodes in the graph"""

    def degree_centrality(self, node_id: str) -> float:
        """
        Basic importance based on connection count.
        Use case: Find the most connected entities.
        """

    def betweenness_centrality(self, node_id: str) -> float:
        """
        Nodes that act as bridges between communities.
        Use case: Find infrastructure pivots, key intermediaries.
        """

    def pagerank(self, node_id: str, damping: float = 0.85) -> float:
        """
        Influence based on who links to you.
        Use case: Identify authoritative threat actors, key domains.
        """

    def eigenvector_centrality(self, node_id: str) -> float:
        """
        Importance based on connections to important nodes.
        Use case: Find well-connected inner circle entities.
        """

    def closeness_centrality(self, node_id: str) -> float:
        """
        How quickly can this node reach all others?
        Use case: Find entities positioned for rapid info spread.
        """

    def harmonic_centrality(self, node_id: str) -> float:
        """
        Closeness that handles disconnected graphs.
        Use case: Importance in fragmented threat networks.
        """
```

### 3.2 Community Detection

```python
class CommunityDetection:
    """Identify clusters of related entities"""

    def louvain_communities(self) -> List[Community]:
        """
        Fast community detection via modularity optimization.
        Use case: Auto-cluster threat infrastructure.
        """

    def label_propagation(self) -> List[Community]:
        """
        Near-linear time community detection.
        Use case: Real-time clustering of streaming entities.
        """

    def strongly_connected_components(self) -> List[List[str]]:
        """
        Find tightly connected subgraphs.
        Use case: Identify coordinated infrastructure.
        """

    def k_core_decomposition(self, k: int) -> List[str]:
        """
        Find densely connected core of the graph.
        Use case: Identify the core threat actor network.
        """

    def triangle_count(self, node_id: str) -> int:
        """
        Count triangles a node participates in.
        Use case: Measure local clustering/collusion.
        """
```

### 3.3 Path Analysis

```python
class PathAnalysis:
    """Discover connections between entities"""

    def shortest_path(
        self,
        source_id: str,
        target_id: str,
        max_hops: int = 6
    ) -> List[PathResult]:
        """
        Find shortest connection between two entities.
        Use case: "How is this IP connected to that threat actor?"
        """

    def all_paths(
        self,
        source_id: str,
        target_id: str,
        max_hops: int = 4,
        max_paths: int = 10
    ) -> List[PathResult]:
        """
        Find all paths between entities.
        Use case: Discover multiple connection vectors.
        """

    def weighted_shortest_path(
        self,
        source_id: str,
        target_id: str,
        weight_property: str = "confidence"
    ) -> PathResult:
        """
        Shortest path considering edge weights.
        Use case: Most reliable connection path.
        """

    def path_exists(
        self,
        source_id: str,
        target_id: str,
        relationship_types: List[str] = None
    ) -> bool:
        """
        Check if any path exists between entities.
        Use case: Quick connectivity check.
        """
```

### 3.4 Similarity & Link Prediction

```python
class SimilarityAnalysis:
    """Find similar entities and predict new relationships"""

    def jaccard_similarity(self, node_a: str, node_b: str) -> float:
        """
        Similarity based on shared neighbors.
        Use case: Find entities with similar connections.
        """

    def cosine_similarity(self, node_a: str, node_b: str) -> float:
        """
        Vector-based similarity of node properties.
        Use case: Find similar threat indicators.
        """

    def node2vec_embedding(self, node_id: str) -> List[float]:
        """
        Learn node embeddings via random walks.
        Use case: ML-ready entity representations.
        """

    def predict_links(
        self,
        node_id: str,
        top_k: int = 10
    ) -> List[LinkPrediction]:
        """
        Predict likely missing relationships.
        Use case: Discover hidden connections.
        """

    def find_similar_nodes(
        self,
        node_id: str,
        entity_type: str = None,
        top_k: int = 10
    ) -> List[SimilarityResult]:
        """
        Find most similar entities in the graph.
        Use case: "Find entities like this threat actor."
        """
```

### 3.5 Anomaly Detection

```python
class GraphAnomalyDetection:
    """Detect unusual patterns in the graph"""

    def outlier_detection(
        self,
        entity_type: str = None
    ) -> List[AnomalyResult]:
        """
        Find entities with unusual graph properties.
        Use case: Detect suspicious infrastructure.
        """

    def temporal_anomalies(
        self,
        time_window: timedelta
    ) -> List[AnomalyResult]:
        """
        Find unusual changes in entity relationships.
        Use case: Detect infrastructure pivots.
        """

    def community_outliers(self) -> List[AnomalyResult]:
        """
        Find nodes that don't fit their community.
        Use case: Detect infiltration or misattribution.
        """

    def bridge_detection(self) -> List[str]:
        """
        Find nodes connecting otherwise separate groups.
        Use case: Identify key pivot points.
        """
```

### 3.6 Influence Propagation

```python
class InfluencePropagation:
    """Model how effects spread through the graph"""

    def infection_simulation(
        self,
        seed_nodes: List[str],
        propagation_probability: float = 0.3,
        max_iterations: int = 10
    ) -> PropagationResult:
        """
        Simulate spread from compromised nodes.
        Use case: "If this server is breached, what's at risk?"
        """

    def influence_maximization(
        self,
        budget: int,
        target_type: str = None
    ) -> List[str]:
        """
        Find optimal nodes to maximize influence.
        Use case: Identify highest-value targets.
        """

    def cascade_analysis(
        self,
        event_node: str,
        max_hops: int = 3
    ) -> CascadeResult:
        """
        Analyze downstream impact of an event.
        Use case: Breach impact assessment.
        """
```

---

## 4. Graph Query Language

### 4.1 Query Interface

```python
class GraphQueryLanguage:
    """
    Cypher-inspired query language for OSINT graphs.
    Translates to Neo4j Cypher under the hood.
    """

    def query(self, gql: str, params: Dict = None) -> QueryResult:
        """
        Execute a GQL query.

        Examples:

        # Find all paths from domain to threat actor
        MATCH path = (d:DOMAIN {value: 'evil.com'})-[*1..4]-(ta:THREAT_ACTOR)
        RETURN path

        # Find infrastructure shared between actors
        MATCH (a1:THREAT_ACTOR)-[:USES]->(infra)<-[:USES]-(a2:THREAT_ACTOR)
        WHERE a1 <> a2
        RETURN a1, infra, a2

        # Find high-centrality domains
        MATCH (d:DOMAIN)
        WHERE d.pagerank > 0.5
        RETURN d ORDER BY d.pagerank DESC LIMIT 20

        # Temporal query - recent relationships
        MATCH (e1)-[r]->(e2)
        WHERE r.last_observed > datetime('2025-01-01')
        RETURN e1, r, e2
        """
```

### 4.2 Pattern Matching

```python
class PatternMatcher:
    """Pre-defined threat patterns for detection"""

    PATTERNS = {
        "c2_infrastructure": """
            MATCH (mal:MALWARE)-[:COMMUNICATES_WITH]->(c2:DOMAIN)
            MATCH (c2)-[:RESOLVES_TO]->(ip:IP_ADDRESS)
            RETURN mal, c2, ip
        """,

        "shared_hosting": """
            MATCH (d1:DOMAIN)-[:RESOLVES_TO]->(ip:IP_ADDRESS)<-[:RESOLVES_TO]-(d2:DOMAIN)
            WHERE d1 <> d2
            RETURN d1, ip, d2, count(*) as shared_count
            ORDER BY shared_count DESC
        """,

        "email_domain_pivot": """
            MATCH (e:EMAIL)-[:ASSOCIATED_WITH]->(d:DOMAIN)
            MATCH (d)-[:REGISTERED_BY]->(reg:PERSON)
            RETURN e, d, reg
        """,

        "certificate_clustering": """
            MATCH (c:CERTIFICATE)-[:ISSUED_FOR]->(d:DOMAIN)
            WITH c, collect(d) as domains
            WHERE size(domains) > 5
            RETURN c, domains
        """,

        "actor_infrastructure_overlap": """
            MATCH (a1:THREAT_ACTOR)-[:ATTRIBUTED_TO]->(campaign1)-[:USES]->(infra)
            MATCH (a2:THREAT_ACTOR)-[:ATTRIBUTED_TO]->(campaign2)-[:USES]->(infra)
            WHERE a1 <> a2
            RETURN a1, a2, collect(DISTINCT infra) as shared_infra
        """,

        "lateral_movement_path": """
            MATCH path = (entry:IP_ADDRESS {tag: 'external'})
                -[:CONNECTS_TO*1..5]->
                (target:IP_ADDRESS {tag: 'internal'})
            RETURN path, length(path) as hops
            ORDER BY hops ASC
        """,

        "data_exfil_path": """
            MATCH path = (data:DATA_STORE)-[*1..4]->(ext:DOMAIN {risk_score: > 70})
            RETURN path
        """
    }

    def match_pattern(self, pattern_name: str) -> List[MatchResult]:
        """Execute a pre-defined pattern query"""

    def custom_pattern(self, pattern: str) -> List[MatchResult]:
        """Execute a custom pattern query"""
```

---

## 5. API Design

### 5.1 REST Endpoints

```yaml
# Graph Intelligence API Endpoints

# Entity Operations
POST   /api/graph/entities                    # Create entity
GET    /api/graph/entities/{id}               # Get entity
PUT    /api/graph/entities/{id}               # Update entity
DELETE /api/graph/entities/{id}               # Delete entity
GET    /api/graph/entities/{id}/neighbors     # Get neighbors
GET    /api/graph/entities/{id}/subgraph      # Get local subgraph

# Relationship Operations
POST   /api/graph/relationships               # Create relationship
GET    /api/graph/relationships/{id}          # Get relationship
DELETE /api/graph/relationships/{id}          # Delete relationship

# Path Analysis
POST   /api/graph/paths/shortest              # Find shortest path
POST   /api/graph/paths/all                   # Find all paths
POST   /api/graph/paths/exists                # Check path existence

# Algorithms
POST   /api/graph/algorithms/centrality       # Run centrality analysis
POST   /api/graph/algorithms/communities      # Detect communities
POST   /api/graph/algorithms/similarity       # Find similar entities
POST   /api/graph/algorithms/anomalies        # Detect anomalies
POST   /api/graph/algorithms/propagation      # Simulate propagation

# Pattern Matching
GET    /api/graph/patterns                    # List available patterns
POST   /api/graph/patterns/match              # Execute pattern match
POST   /api/graph/patterns/custom             # Custom pattern query

# Query
POST   /api/graph/query                       # Execute GQL query

# Visualization
GET    /api/graph/viz/subgraph/{id}           # Get visualization data
GET    /api/graph/viz/investigation/{id}      # Investigation graph
POST   /api/graph/viz/export                  # Export graph (GEXF, GraphML)

# Statistics
GET    /api/graph/stats                       # Graph statistics
GET    /api/graph/stats/entity-types          # Entity type distribution
GET    /api/graph/stats/relationship-types    # Relationship distribution
```

### 5.2 Request/Response Examples

```json
// POST /api/graph/paths/shortest
// Request
{
  "source_id": "entity_abc123",
  "target_id": "entity_xyz789",
  "max_hops": 6,
  "relationship_types": ["RESOLVES_TO", "HOSTS", "REGISTERED_BY"],
  "include_properties": true
}

// Response
{
  "found": true,
  "path_length": 3,
  "path": {
    "nodes": [
      {"id": "entity_abc123", "type": "DOMAIN", "value": "malware.com"},
      {"id": "entity_def456", "type": "IP_ADDRESS", "value": "192.168.1.1"},
      {"id": "entity_ghi789", "type": "PERSON", "value": "John Doe"},
      {"id": "entity_xyz789", "type": "ORGANIZATION", "value": "Evil Corp"}
    ],
    "edges": [
      {"type": "RESOLVES_TO", "confidence": 0.95},
      {"type": "REGISTERED_BY", "confidence": 0.87},
      {"type": "WORKS_FOR", "confidence": 0.72}
    ]
  },
  "total_confidence": 0.60,
  "computation_time_ms": 45
}
```

```json
// POST /api/graph/algorithms/communities
// Request
{
  "algorithm": "louvain",
  "entity_types": ["DOMAIN", "IP_ADDRESS"],
  "min_community_size": 3,
  "resolution": 1.0
}

// Response
{
  "communities": [
    {
      "community_id": "comm_001",
      "size": 47,
      "density": 0.34,
      "entity_types": {"DOMAIN": 32, "IP_ADDRESS": 15},
      "central_entities": [
        {"id": "entity_abc", "value": "c2-server.net", "centrality": 0.89}
      ],
      "tags": ["botnet_infrastructure"],
      "risk_score": 85
    },
    {
      "community_id": "comm_002",
      "size": 23,
      "density": 0.56,
      "entity_types": {"DOMAIN": 18, "IP_ADDRESS": 5},
      "central_entities": [
        {"id": "entity_def", "value": "phishing-kit.com", "centrality": 0.76}
      ],
      "tags": ["phishing_campaign"],
      "risk_score": 72
    }
  ],
  "modularity_score": 0.67,
  "total_communities": 12,
  "computation_time_ms": 234
}
```

---

## 6. Integration Architecture

### 6.1 Correlation Engine Integration

```python
class GraphIntegrationService:
    """Bridge between existing correlation engine and graph database"""

    def sync_correlation_result(
        self,
        correlation_result: CorrelationResult,
        investigation_id: str
    ) -> SyncResult:
        """
        Sync correlation results to persistent graph.

        1. Upsert all entities as graph nodes
        2. Upsert all relationships as graph edges
        3. Link to investigation node
        4. Trigger algorithm updates (async)
        """

    def enrich_from_graph(
        self,
        entity_ids: List[str]
    ) -> EnrichmentResult:
        """
        Enrich entities with graph-computed properties.

        - Add centrality scores
        - Add community membership
        - Add related entities from other investigations
        - Add historical relationship data
        """

    def cross_investigation_correlation(
        self,
        investigation_id: str
    ) -> CrossCorrelationResult:
        """
        Find entities shared across investigations.

        Use case: "Has this infrastructure appeared before?"
        """
```

### 6.2 MCP Server Integration

```python
class GraphMCPIntegration:
    """Ingest intelligence from MCP servers into graph"""

    def ingest_infrastructure_intel(
        self,
        intel: Dict[str, Any],
        source: str
    ) -> IngestResult:
        """Process infrastructure MCP server output"""

    def ingest_threat_intel(
        self,
        intel: Dict[str, Any],
        source: str
    ) -> IngestResult:
        """Process threat MCP server output"""

    def ingest_stix_bundle(
        self,
        stix_bundle: Dict[str, Any]
    ) -> IngestResult:
        """Ingest STIX 2.1 formatted threat intelligence"""
```

### 6.3 Real-Time Stream Processing

```python
class GraphStreamProcessor:
    """Process entity/relationship changes in real-time"""

    def __init__(self, redis_client, neo4j_driver):
        self.redis = redis_client
        self.neo4j = neo4j_driver
        self.subscribers = []

    async def process_entity_event(self, event: EntityEvent):
        """
        Handle entity creation/update/deletion.

        1. Update graph database
        2. Invalidate affected caches
        3. Check alert triggers
        4. Notify subscribers
        """

    async def process_relationship_event(self, event: RelationshipEvent):
        """
        Handle relationship changes.

        1. Update graph database
        2. Recompute affected centrality (async)
        3. Check pattern triggers
        4. Notify subscribers
        """

    def subscribe(
        self,
        pattern: str,
        callback: Callable
    ) -> SubscriptionId:
        """
        Subscribe to graph events matching pattern.

        Example patterns:
        - "entity:THREAT_ACTOR:*" - All threat actor changes
        - "relationship:ATTRIBUTED_TO:*" - Attribution changes
        - "community:*" - Community membership changes
        """
```

---

## 7. Visualization Data Structures

### 7.1 Graph Visualization Export

```python
@dataclass
class GraphVisualization:
    """Data structure for frontend graph rendering"""

    nodes: List[VisNode]
    edges: List[VisEdge]
    layout: LayoutConfig
    metadata: GraphMetadata

@dataclass
class VisNode:
    """Node for visualization"""
    id: str
    label: str
    type: str

    # Visual properties
    size: float           # Based on centrality
    color: str            # Based on entity type or risk
    icon: str             # Entity type icon

    # Position (if pre-computed)
    x: Optional[float]
    y: Optional[float]

    # Interaction
    tooltip: str
    details_url: str

    # Grouping
    community_id: Optional[str]
    cluster_position: Optional[Tuple[float, float]]

@dataclass
class VisEdge:
    """Edge for visualization"""
    id: str
    source: str
    target: str
    type: str

    # Visual properties
    width: float          # Based on confidence/weight
    color: str            # Based on relationship type
    style: str            # solid, dashed, dotted

    # Labels
    label: Optional[str]
    tooltip: str

    # Animation
    animated: bool        # For active/recent relationships

@dataclass
class LayoutConfig:
    """Graph layout configuration"""
    algorithm: str        # force-directed, hierarchical, radial
    spacing: float
    gravity: float
    repulsion: float

    # Clustering
    cluster_by: Optional[str]  # community, entity_type, risk_level
    cluster_spacing: float
```

### 7.2 Timeline Visualization

```python
@dataclass
class GraphTimeline:
    """Temporal evolution of the graph"""

    snapshots: List[TimelineSnapshot]
    events: List[GraphEvent]

@dataclass
class TimelineSnapshot:
    """Graph state at a point in time"""
    timestamp: datetime
    node_count: int
    edge_count: int
    community_count: int
    key_changes: List[str]

@dataclass
class GraphEvent:
    """Significant graph event"""
    timestamp: datetime
    event_type: str       # node_added, edge_added, community_formed, etc.
    entities: List[str]
    description: str
    significance: float   # 0.0-1.0
```

---

## 8. Storage Architecture

### 8.1 Neo4j Schema

```cypher
// Node indexes for fast lookup
CREATE INDEX entity_id_idx FOR (n:Entity) ON (n.entity_id);
CREATE INDEX entity_type_idx FOR (n:Entity) ON (n.entity_type);
CREATE INDEX entity_value_idx FOR (n:Entity) ON (n.normalized_value);
CREATE INDEX entity_risk_idx FOR (n:Entity) ON (n.risk_score);

// Composite indexes for common queries
CREATE INDEX entity_type_value_idx FOR (n:Entity) ON (n.entity_type, n.normalized_value);

// Full-text search index
CREATE FULLTEXT INDEX entity_search FOR (n:Entity) ON EACH [n.value, n.label];

// Relationship indexes
CREATE INDEX rel_type_idx FOR ()-[r:RELATES_TO]-() ON (r.relationship_type);
CREATE INDEX rel_confidence_idx FOR ()-[r:RELATES_TO]-() ON (r.confidence);
CREATE INDEX rel_temporal_idx FOR ()-[r:RELATES_TO]-() ON (r.last_observed);

// Investigation linkage
CREATE INDEX investigation_idx FOR (n:Entity) ON (n.investigation_ids);

// Example node labels (one per entity type)
// :Domain, :IpAddress, :Email, :Person, :Organization, :ThreatActor, etc.
```

### 8.2 Redis Cache Strategy

```python
CACHE_KEYS = {
    # Entity cache (TTL: 5 min)
    "entity:{entity_id}": "Full entity data",

    # Neighbors cache (TTL: 2 min)
    "neighbors:{entity_id}:{depth}": "Neighbor list at depth",

    # Algorithm results (TTL: 15 min)
    "centrality:{entity_id}": "Centrality scores",
    "community:{entity_id}": "Community membership",

    # Path cache (TTL: 5 min)
    "path:{source_id}:{target_id}": "Shortest path result",

    # Pattern cache (TTL: 10 min)
    "pattern:{pattern_name}:{hash}": "Pattern match results",

    # Query cache (TTL: 5 min)
    "query:{query_hash}": "GQL query results",

    # Visualization cache (TTL: 5 min)
    "viz:{investigation_id}": "Visualization data",
}
```

### 8.3 PostgreSQL Metadata

```sql
-- Graph operation audit log
CREATE TABLE graph_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation VARCHAR(50) NOT NULL,  -- create_entity, delete_edge, run_algorithm
    entity_id VARCHAR(100),
    user_id VARCHAR(100),
    investigation_id UUID,
    details JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Algorithm job history
CREATE TABLE graph_algorithm_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    algorithm VARCHAR(100) NOT NULL,
    parameters JSONB,
    status VARCHAR(20) DEFAULT 'pending',
    result_summary JSONB,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT
);

-- Saved graph queries
CREATE TABLE saved_queries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    query_gql TEXT NOT NULL,
    parameters JSONB,
    user_id VARCHAR(100),
    is_public BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Alert triggers based on graph patterns
CREATE TABLE graph_alert_triggers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    pattern_gql TEXT NOT NULL,
    severity VARCHAR(20) DEFAULT 'medium',
    notification_channels JSONB,
    enabled BOOLEAN DEFAULT true,
    last_triggered_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);
```

---

## 9. Implementation Roadmap

### Phase 1: Foundation (Week 1-2)
- [ ] Neo4j setup and schema definition
- [ ] GraphNode and GraphEdge data models
- [ ] Basic CRUD operations for entities/relationships
- [ ] Integration with existing IntelligenceCorrelator

### Phase 2: Core Algorithms (Week 3-4)
- [ ] Centrality algorithms (degree, betweenness, PageRank)
- [ ] Path finding (shortest path, all paths)
- [ ] Community detection (Louvain)
- [ ] Algorithm result caching

### Phase 3: Query & Patterns (Week 5-6)
- [ ] Graph Query Language parser
- [ ] Pre-defined pattern library
- [ ] Custom pattern execution
- [ ] Query optimization

### Phase 4: API & Integration (Week 7-8)
- [ ] REST API endpoints
- [ ] MCP server integration
- [ ] Cross-investigation correlation
- [ ] Real-time stream processing

### Phase 5: Visualization (Week 9-10)
- [ ] Visualization data export
- [ ] Layout algorithms
- [ ] Timeline generation
- [ ] Frontend integration

### Phase 6: Advanced Features (Week 11-12)
- [ ] Similarity analysis
- [ ] Link prediction
- [ ] Anomaly detection
- [ ] Influence propagation

---

## 10. File Structure

```
simple-backend/
├── graph_intelligence/
│   ├── __init__.py
│   ├── models.py              # GraphNode, GraphEdge, extended types
│   ├── service.py             # GraphIntelligenceService main class
│   ├── neo4j_client.py        # Neo4j connection and queries
│   ├── algorithms/
│   │   ├── __init__.py
│   │   ├── centrality.py      # Centrality algorithms
│   │   ├── community.py       # Community detection
│   │   ├── paths.py           # Path analysis
│   │   ├── similarity.py      # Similarity & link prediction
│   │   ├── anomaly.py         # Anomaly detection
│   │   └── propagation.py     # Influence propagation
│   ├── query/
│   │   ├── __init__.py
│   │   ├── gql_parser.py      # GQL to Cypher translation
│   │   ├── patterns.py        # Pre-defined patterns
│   │   └── optimizer.py       # Query optimization
│   ├── integration/
│   │   ├── __init__.py
│   │   ├── correlation_sync.py # Sync with correlation engine
│   │   ├── mcp_ingest.py      # MCP server integration
│   │   └── stix_import.py     # STIX/TAXII import
│   ├── streaming/
│   │   ├── __init__.py
│   │   └── processor.py       # Real-time event processing
│   └── visualization/
│       ├── __init__.py
│       ├── export.py          # Graph export formats
│       └── layout.py          # Layout algorithms
├── tests/
│   └── graph_intelligence/
│       ├── test_models.py
│       ├── test_algorithms.py
│       ├── test_query.py
│       └── test_integration.py
```

---

## 11. Dependencies

```txt
# Graph database
neo4j>=5.15.0
py2neo>=2021.2.3

# Graph algorithms (for non-Neo4j computations)
networkx>=3.2
python-louvain>=0.16
node2vec>=0.4.6

# Caching
redis>=5.0.0

# Async processing
celery>=5.3.0
aioredis>=2.0.0

# Data validation
pydantic>=2.5.0

# STIX support
stix2>=3.0.1
taxii2-client>=2.3.0
```

---

## 12. Configuration

```yaml
# config/graph_intelligence.yaml

neo4j:
  uri: "bolt://localhost:7687"
  username: "${NEO4J_USERNAME}"
  password: "${NEO4J_PASSWORD}"
  database: "osint_graph"
  max_connection_pool_size: 50
  connection_timeout: 30

redis:
  host: "localhost"
  port: 6379
  db: 1
  cache_ttl_seconds: 300

algorithms:
  centrality:
    batch_size: 1000
    update_interval_minutes: 15
  community:
    algorithm: "louvain"
    resolution: 1.0
    min_community_size: 3
  paths:
    max_depth: 6
    max_paths: 100

streaming:
  enabled: true
  batch_size: 100
  flush_interval_ms: 1000

visualization:
  default_layout: "force-directed"
  max_nodes_interactive: 500
  max_nodes_static: 5000
```

---

This architecture provides the foundation for Palantir-like graph intelligence capabilities while integrating seamlessly with the existing OSINT platform infrastructure.
