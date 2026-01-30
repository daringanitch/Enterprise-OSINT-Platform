#!/usr/bin/env python3
"""
Graph Intelligence Engine - Core Models

Defines data structures for the graph intelligence system including:
- Extended entity and relationship types
- Graph nodes and edges with full metadata
- Algorithm result structures
- Query and pattern matching models
- Visualization data structures
"""

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union


# =============================================================================
# EXTENDED ENTITY TYPES
# =============================================================================

class ExtendedEntityType(Enum):
    """
    Extended entity types for comprehensive graph intelligence.
    Includes original OSINT types plus advanced threat and business entities.
    """

    # Core OSINT entities (from intelligence_correlation.py)
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

    # Geospatial entities
    LOCATION = "location"
    ADDRESS = "address"
    COUNTRY = "country"
    REGION = "region"

    # Financial entities
    CRYPTOCURRENCY_WALLET = "crypto_wallet"
    BANK_ACCOUNT = "bank_account"
    TRANSACTION = "transaction"
    FINANCIAL_INSTRUMENT = "financial_instrument"

    # Threat intelligence entities
    THREAT_ACTOR = "threat_actor"
    CAMPAIGN = "campaign"
    MALWARE_FAMILY = "malware_family"
    VULNERABILITY = "vulnerability"  # CVE
    EXPLOIT = "exploit"
    ATTACK_PATTERN = "attack_pattern"  # MITRE technique
    TOOL = "tool"  # Hacking tool
    INTRUSION_SET = "intrusion_set"

    # Infrastructure entities
    DEVICE = "device"
    SOFTWARE = "software"
    NETWORK_SEGMENT = "network_segment"
    CLOUD_RESOURCE = "cloud_resource"
    CONTAINER = "container"

    # Data and documents
    DOCUMENT = "document"
    DATA_BREACH = "data_breach"
    CREDENTIAL = "credential"
    FILE = "file"
    DATABASE = "database"

    # Business entities
    LEGAL_ENTITY = "legal_entity"
    SUBSIDIARY = "subsidiary"
    BRAND = "brand"
    PRODUCT = "product"

    # Temporal entities
    EVENT = "event"
    INCIDENT = "incident"
    TIMESTAMP = "timestamp"

    # Communication entities
    PHONE_NUMBER = "phone_number"
    MESSAGING_ACCOUNT = "messaging_account"
    FORUM_POST = "forum_post"

    @classmethod
    def from_string(cls, value: str) -> "ExtendedEntityType":
        """Convert string to EntityType, with fallback."""
        try:
            return cls(value.lower())
        except ValueError:
            # Map legacy types
            legacy_map = {
                "ip": cls.IP_ADDRESS,
                "dns": cls.DOMAIN,
                "hostname": cls.DOMAIN,
                "sha256": cls.HASH,
                "md5": cls.HASH,
                "sha1": cls.HASH,
                "cve": cls.VULNERABILITY,
                "apt": cls.THREAT_ACTOR,
            }
            return legacy_map.get(value.lower(), cls.ORGANIZATION)

    @property
    def category(self) -> str:
        """Get the category of this entity type."""
        categories = {
            # Infrastructure
            "infrastructure": [
                self.DOMAIN, self.IP_ADDRESS, self.ASN, self.CERTIFICATE,
                self.TECHNOLOGY, self.DEVICE, self.SOFTWARE, self.NETWORK_SEGMENT,
                self.CLOUD_RESOURCE, self.CONTAINER
            ],
            # Identity
            "identity": [
                self.PERSON, self.EMAIL, self.PHONE, self.PHONE_NUMBER,
                self.SOCIAL_ACCOUNT, self.MESSAGING_ACCOUNT, self.CREDENTIAL
            ],
            # Threat
            "threat": [
                self.THREAT_ACTOR, self.CAMPAIGN, self.MALWARE_FAMILY,
                self.VULNERABILITY, self.EXPLOIT, self.ATTACK_PATTERN,
                self.TOOL, self.INTRUSION_SET, self.HASH
            ],
            # Business
            "business": [
                self.ORGANIZATION, self.LEGAL_ENTITY, self.SUBSIDIARY,
                self.BRAND, self.PRODUCT
            ],
            # Financial
            "financial": [
                self.CRYPTOCURRENCY_WALLET, self.BANK_ACCOUNT,
                self.TRANSACTION, self.FINANCIAL_INSTRUMENT
            ],
            # Geospatial
            "geospatial": [
                self.LOCATION, self.ADDRESS, self.COUNTRY, self.REGION
            ],
            # Data
            "data": [
                self.URL, self.DOCUMENT, self.DATA_BREACH, self.FILE, self.DATABASE
            ],
            # Temporal
            "temporal": [
                self.EVENT, self.INCIDENT, self.TIMESTAMP
            ],
        }

        for category, types in categories.items():
            if self in types:
                return category
        return "other"

    @property
    def icon(self) -> str:
        """Get icon identifier for visualization."""
        icons = {
            self.DOMAIN: "globe",
            self.IP_ADDRESS: "server",
            self.EMAIL: "mail",
            self.PERSON: "user",
            self.ORGANIZATION: "building",
            self.URL: "link",
            self.HASH: "fingerprint",
            self.PHONE: "phone",
            self.SOCIAL_ACCOUNT: "share-2",
            self.CERTIFICATE: "shield",
            self.ASN: "network",
            self.TECHNOLOGY: "cpu",
            self.LOCATION: "map-pin",
            self.CRYPTOCURRENCY_WALLET: "bitcoin",
            self.THREAT_ACTOR: "skull",
            self.CAMPAIGN: "target",
            self.MALWARE_FAMILY: "bug",
            self.VULNERABILITY: "alert-triangle",
            self.DEVICE: "monitor",
            self.DATA_BREACH: "database",
            self.LEGAL_ENTITY: "briefcase",
            self.EVENT: "calendar",
        }
        return icons.get(self, "circle")

    @property
    def color(self) -> str:
        """Get color for visualization."""
        colors = {
            "infrastructure": "#3B82F6",  # Blue
            "identity": "#10B981",         # Green
            "threat": "#EF4444",           # Red
            "business": "#8B5CF6",         # Purple
            "financial": "#F59E0B",        # Amber
            "geospatial": "#06B6D4",       # Cyan
            "data": "#6366F1",             # Indigo
            "temporal": "#EC4899",         # Pink
        }
        return colors.get(self.category, "#6B7280")


# =============================================================================
# EXTENDED RELATIONSHIP TYPES
# =============================================================================

class ExtendedRelationshipType(Enum):
    """
    Extended relationship types for rich graph modeling.
    Supports infrastructure, threat, financial, and social relationships.
    """

    # Core infrastructure relationships
    RESOLVES_TO = "resolves_to"           # Domain -> IP
    HOSTS = "hosts"                        # IP -> Domain
    REGISTERED_BY = "registered_by"        # Domain -> Person/Email
    OWNS = "owns"                          # Organization -> Domain
    SUBDOMAIN_OF = "subdomain_of"          # Subdomain -> Parent
    ISSUED_FOR = "issued_for"              # Certificate -> Domain
    USES_TECHNOLOGY = "uses_technology"    # Domain -> Technology
    ASSOCIATED_WITH = "associated_with"    # Generic association

    # Network relationships
    ROUTES_THROUGH = "routes_through"      # Traffic routing
    PEERS_WITH = "peers_with"              # BGP peering
    UPSTREAM_OF = "upstream_of"            # AS relationship
    DOWNSTREAM_OF = "downstream_of"        # AS relationship
    SHARES_INFRASTRUCTURE = "shares_infrastructure"
    COLOCATED_WITH = "colocated_with"      # Same datacenter/host
    PROXIED_BY = "proxied_by"              # CDN/proxy relationship
    TUNNELS_TO = "tunnels_to"              # VPN/tunnel

    # DNS relationships
    CNAME_OF = "cname_of"
    MX_FOR = "mx_for"
    NS_FOR = "ns_for"
    HISTORICALLY_RESOLVED = "historically_resolved"

    # Threat relationships
    ATTRIBUTED_TO = "attributed_to"        # Attack -> Actor
    TARGETS = "targets"                    # Actor -> Target
    EXPLOITS = "exploits"                  # Malware -> Vulnerability
    DELIVERS = "delivers"                  # Campaign -> Malware
    COMMUNICATES_WITH = "communicates_with"  # Malware -> C2
    DOWNLOADS_FROM = "downloads_from"      # Malware -> URL
    DROPS = "drops"                        # Malware -> Malware
    SIMILAR_TO = "similar_to"              # Code similarity
    VARIANT_OF = "variant_of"              # Malware variant
    PART_OF = "part_of"                    # Campaign membership
    USES_TECHNIQUE = "uses_technique"      # Actor -> MITRE
    INDICATES = "indicates"                # IOC -> Threat

    # Person/Organization relationships
    MEMBER_OF = "member_of"                # Person -> Organization
    WORKS_FOR = "works_for"                # Employment
    CONTROLS = "controls"                  # Person -> Account
    KNOWS = "knows"                        # Social connection
    RELATED_TO = "related_to"              # Family/business
    ALIASES = "aliases"                    # Same entity, different name
    IMPERSONATES = "impersonates"          # Fraud/phishing
    MENTIONED_BY = "mentioned_by"          # Social mention
    FOLLOWS = "follows"                    # Social following

    # Financial relationships
    TRANSACTS_WITH = "transacts_with"      # Financial transaction
    FUNDS = "funds"                        # Funding relationship
    RECEIVES_FROM = "receives_from"        # Payment receipt
    SENDS_TO = "sends_to"                  # Payment sending
    SUBSIDIARY_OF = "subsidiary_of"        # Corporate structure
    INVESTS_IN = "invests_in"              # Investment
    ACQUIRED_BY = "acquired_by"            # M&A

    # Data relationships
    EXPOSED_IN = "exposed_in"              # Credential -> Breach
    CONTAINS = "contains"                  # Document -> Entity
    REFERENCES = "references"              # Document -> Entity
    MENTIONS = "mentions"                  # Text -> Entity
    STORED_IN = "stored_in"                # Data -> Database
    LEAKED_BY = "leaked_by"                # Data -> Breach

    # Temporal relationships
    PRECEDED_BY = "preceded_by"            # Event sequence
    FOLLOWED_BY = "followed_by"            # Event sequence
    CONCURRENT_WITH = "concurrent_with"    # Same time
    CAUSED_BY = "caused_by"                # Causation
    RESULTED_IN = "resulted_in"            # Consequence

    # Location relationships
    LOCATED_IN = "located_in"              # Entity -> Location
    TRAVELED_TO = "traveled_to"            # Movement
    OPERATES_IN = "operates_in"            # Business operation
    ORIGINATED_FROM = "originated_from"    # Source location

    @classmethod
    def from_string(cls, value: str) -> "ExtendedRelationshipType":
        """Convert string to RelationshipType."""
        try:
            return cls(value.lower())
        except ValueError:
            return cls.ASSOCIATED_WITH

    @property
    def is_directional(self) -> bool:
        """Check if this relationship type is directional."""
        bidirectional = {
            self.ASSOCIATED_WITH,
            self.SHARES_INFRASTRUCTURE,
            self.COLOCATED_WITH,
            self.PEERS_WITH,
            self.SIMILAR_TO,
            self.KNOWS,
            self.RELATED_TO,
            self.CONCURRENT_WITH,
        }
        return self not in bidirectional

    @property
    def inverse(self) -> Optional["ExtendedRelationshipType"]:
        """Get the inverse relationship type if applicable."""
        inverses = {
            self.RESOLVES_TO: self.HOSTS,
            self.HOSTS: self.RESOLVES_TO,
            self.UPSTREAM_OF: self.DOWNSTREAM_OF,
            self.DOWNSTREAM_OF: self.UPSTREAM_OF,
            self.PRECEDED_BY: self.FOLLOWED_BY,
            self.FOLLOWED_BY: self.PRECEDED_BY,
            self.CAUSED_BY: self.RESULTED_IN,
            self.RESULTED_IN: self.CAUSED_BY,
            self.SENDS_TO: self.RECEIVES_FROM,
            self.RECEIVES_FROM: self.SENDS_TO,
            self.FUNDS: self.RECEIVES_FROM,
            self.CONTAINS: None,  # No inverse
            self.PART_OF: None,
        }
        return inverses.get(self)

    @property
    def weight_default(self) -> float:
        """Default weight for this relationship type."""
        high_weight = {
            self.RESOLVES_TO, self.HOSTS, self.OWNS,
            self.ATTRIBUTED_TO, self.DELIVERS, self.EXPLOITS,
            self.WORKS_FOR, self.MEMBER_OF,
        }
        medium_weight = {
            self.ASSOCIATED_WITH, self.SIMILAR_TO,
            self.SHARES_INFRASTRUCTURE, self.COMMUNICATES_WITH,
        }
        if self in high_weight:
            return 1.0
        elif self in medium_weight:
            return 0.7
        return 0.5

    @property
    def color(self) -> str:
        """Color for visualization."""
        threat_rels = {
            self.ATTRIBUTED_TO, self.TARGETS, self.EXPLOITS,
            self.DELIVERS, self.COMMUNICATES_WITH, self.INDICATES
        }
        financial_rels = {
            self.TRANSACTS_WITH, self.FUNDS, self.SENDS_TO,
            self.RECEIVES_FROM, self.INVESTS_IN
        }
        infra_rels = {
            self.RESOLVES_TO, self.HOSTS, self.SUBDOMAIN_OF,
            self.ROUTES_THROUGH, self.COLOCATED_WITH
        }

        if self in threat_rels:
            return "#EF4444"  # Red
        elif self in financial_rels:
            return "#F59E0B"  # Amber
        elif self in infra_rels:
            return "#3B82F6"  # Blue
        return "#6B7280"  # Gray


# =============================================================================
# GRAPH NODE MODEL
# =============================================================================

@dataclass
class GraphNode:
    """
    Persistent graph node representing an entity in the knowledge graph.

    Stores both the entity data and computed graph properties like
    centrality scores and community membership.
    """

    # Core identifiers
    node_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str = ""  # Links to correlation engine entity
    entity_type: ExtendedEntityType = ExtendedEntityType.ORGANIZATION

    # Primary data
    value: str = ""
    normalized_value: str = ""
    label: str = ""

    # Provenance
    sources: List[str] = field(default_factory=list)
    confidence: float = 0.5
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    # Graph topology (computed)
    in_degree: int = 0
    out_degree: int = 0

    # Centrality scores (computed by algorithms)
    degree_centrality: float = 0.0
    betweenness_centrality: float = 0.0
    closeness_centrality: float = 0.0
    eigenvector_centrality: float = 0.0
    pagerank: float = 0.0

    # Community detection (computed)
    community_id: Optional[str] = None
    community_role: str = "member"  # hub, bridge, member, outlier

    # Risk assessment
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    threat_level: str = "unknown"  # critical, high, medium, low, unknown

    # Extended properties
    properties: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)

    # Investigation linkage
    investigation_ids: List[str] = field(default_factory=list)

    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    version: int = 1

    def __post_init__(self):
        """Initialize computed fields."""
        if not self.entity_id:
            self.entity_id = self._generate_entity_id()
        if not self.normalized_value:
            self.normalized_value = self._normalize_value()
        if not self.label:
            self.label = self._generate_label()
        if not self.first_seen:
            self.first_seen = datetime.utcnow()
        if not self.last_seen:
            self.last_seen = datetime.utcnow()

    def _generate_entity_id(self) -> str:
        """Generate deterministic entity ID from type and value."""
        hash_input = f"{self.entity_type.value}:{self.normalized_value or self.value}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]

    def _normalize_value(self) -> str:
        """Normalize the value based on entity type."""
        value = self.value.strip()

        if self.entity_type == ExtendedEntityType.DOMAIN:
            return value.lower().lstrip("www.")
        elif self.entity_type == ExtendedEntityType.EMAIL:
            return value.lower()
        elif self.entity_type == ExtendedEntityType.IP_ADDRESS:
            return value
        elif self.entity_type in (ExtendedEntityType.HASH, ExtendedEntityType.URL):
            return value.lower()
        elif self.entity_type == ExtendedEntityType.PERSON:
            return value.lower().strip()
        else:
            return value.lower()

    def _generate_label(self) -> str:
        """Generate human-readable label."""
        if self.entity_type == ExtendedEntityType.THREAT_ACTOR:
            return f"Actor: {self.value}"
        elif self.entity_type == ExtendedEntityType.CAMPAIGN:
            return f"Campaign: {self.value}"
        elif self.entity_type == ExtendedEntityType.MALWARE_FAMILY:
            return f"Malware: {self.value}"
        elif self.entity_type == ExtendedEntityType.VULNERABILITY:
            return f"Vuln: {self.value}"
        return self.value

    @property
    def total_degree(self) -> int:
        """Total degree (in + out)."""
        return self.in_degree + self.out_degree

    @property
    def centrality_score(self) -> float:
        """Composite centrality score."""
        return (
            self.pagerank * 0.3 +
            self.betweenness_centrality * 0.3 +
            self.degree_centrality * 0.2 +
            self.eigenvector_centrality * 0.2
        )

    def add_source(self, source: str) -> None:
        """Add a source and update confidence."""
        if source not in self.sources:
            self.sources.append(source)
            # Increase confidence with diminishing returns
            self.confidence = min(1.0, self.confidence + (1 - self.confidence) * 0.15)
            self.updated_at = datetime.utcnow()

    def add_tag(self, tag: str) -> None:
        """Add a tag if not present."""
        if tag not in self.tags:
            self.tags.append(tag)
            self.updated_at = datetime.utcnow()

    def add_investigation(self, investigation_id: str) -> None:
        """Link node to an investigation."""
        if investigation_id not in self.investigation_ids:
            self.investigation_ids.append(investigation_id)
            self.updated_at = datetime.utcnow()

    def merge_from(self, other: "GraphNode") -> None:
        """Merge data from another node (same entity)."""
        # Merge sources
        for source in other.sources:
            self.add_source(source)

        # Merge tags
        for tag in other.tags:
            self.add_tag(tag)

        # Merge aliases
        for alias in other.aliases:
            if alias not in self.aliases:
                self.aliases.append(alias)

        # Update timestamps
        if other.first_seen and (not self.first_seen or other.first_seen < self.first_seen):
            self.first_seen = other.first_seen
        if other.last_seen and (not self.last_seen or other.last_seen > self.last_seen):
            self.last_seen = other.last_seen

        # Merge properties
        self.properties.update(other.properties)

        # Merge investigations
        for inv_id in other.investigation_ids:
            self.add_investigation(inv_id)

        self.updated_at = datetime.utcnow()
        self.version += 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "node_id": self.node_id,
            "entity_id": self.entity_id,
            "entity_type": self.entity_type.value,
            "value": self.value,
            "normalized_value": self.normalized_value,
            "label": self.label,
            "sources": self.sources,
            "source_count": len(self.sources),
            "confidence": round(self.confidence, 3),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "in_degree": self.in_degree,
            "out_degree": self.out_degree,
            "total_degree": self.total_degree,
            "centrality": {
                "degree": round(self.degree_centrality, 4),
                "betweenness": round(self.betweenness_centrality, 4),
                "closeness": round(self.closeness_centrality, 4),
                "eigenvector": round(self.eigenvector_centrality, 4),
                "pagerank": round(self.pagerank, 4),
                "composite": round(self.centrality_score, 4),
            },
            "community_id": self.community_id,
            "community_role": self.community_role,
            "risk_score": round(self.risk_score, 1),
            "risk_factors": self.risk_factors,
            "threat_level": self.threat_level,
            "properties": self.properties,
            "tags": self.tags,
            "aliases": self.aliases,
            "investigation_ids": self.investigation_ids,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "version": self.version,
        }

    def to_neo4j_properties(self) -> Dict[str, Any]:
        """Convert to Neo4j-compatible property dict."""
        return {
            "node_id": self.node_id,
            "entity_id": self.entity_id,
            "entity_type": self.entity_type.value,
            "value": self.value,
            "normalized_value": self.normalized_value,
            "label": self.label,
            "sources": self.sources,
            "confidence": self.confidence,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "in_degree": self.in_degree,
            "out_degree": self.out_degree,
            "degree_centrality": self.degree_centrality,
            "betweenness_centrality": self.betweenness_centrality,
            "closeness_centrality": self.closeness_centrality,
            "eigenvector_centrality": self.eigenvector_centrality,
            "pagerank": self.pagerank,
            "community_id": self.community_id,
            "community_role": self.community_role,
            "risk_score": self.risk_score,
            "threat_level": self.threat_level,
            "tags": self.tags,
            "aliases": self.aliases,
            "investigation_ids": self.investigation_ids,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "version": self.version,
        }

    @classmethod
    def from_correlation_entity(cls, entity: Any, investigation_id: str = None) -> "GraphNode":
        """Create GraphNode from correlation engine Entity."""
        # Map legacy EntityType to ExtendedEntityType
        entity_type = ExtendedEntityType.from_string(entity.entity_type.value)

        node = cls(
            entity_id=entity.id,
            entity_type=entity_type,
            value=entity.value,
            normalized_value=entity.normalized_value,
            sources=entity.sources.copy(),
            confidence=entity.confidence,
            first_seen=entity.first_seen,
            last_seen=entity.last_seen,
            tags=entity.tags.copy(),
            properties=entity.attributes.copy(),
        )

        if investigation_id:
            node.add_investigation(investigation_id)

        return node


# =============================================================================
# GRAPH EDGE MODEL
# =============================================================================

@dataclass
class GraphEdge:
    """
    Persistent graph edge representing a relationship between entities.

    Supports weighted edges, temporal tracking, and multi-source evidence.
    """

    # Core identifiers
    edge_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str = ""  # Source node entity_id
    target_id: str = ""  # Target node entity_id
    relationship_type: ExtendedRelationshipType = ExtendedRelationshipType.ASSOCIATED_WITH

    # Relationship strength
    weight: float = 1.0
    confidence: float = 0.5

    # Provenance
    sources: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)

    # Temporal
    first_observed: Optional[datetime] = None
    last_observed: Optional[datetime] = None
    active: bool = True

    # Properties
    attributes: Dict[str, Any] = field(default_factory=dict)
    bidirectional: bool = False

    # Investigation linkage
    investigation_ids: List[str] = field(default_factory=list)

    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    version: int = 1

    def __post_init__(self):
        """Initialize computed fields."""
        if not self.first_observed:
            self.first_observed = datetime.utcnow()
        if not self.last_observed:
            self.last_observed = datetime.utcnow()
        # Set bidirectional based on relationship type
        if not self.relationship_type.is_directional:
            self.bidirectional = True
        # Set default weight
        if self.weight == 1.0:
            self.weight = self.relationship_type.weight_default

    @property
    def composite_weight(self) -> float:
        """Weight adjusted by confidence."""
        return self.weight * self.confidence

    def add_source(self, source: str) -> None:
        """Add a source and update confidence."""
        if source not in self.sources:
            self.sources.append(source)
            self.confidence = min(1.0, self.confidence + (1 - self.confidence) * 0.15)
            self.updated_at = datetime.utcnow()

    def add_evidence(self, evidence: Dict[str, Any]) -> None:
        """Add supporting evidence."""
        self.evidence.append(evidence)
        self.confidence = min(1.0, self.confidence + 0.05)
        self.updated_at = datetime.utcnow()

    def add_investigation(self, investigation_id: str) -> None:
        """Link edge to an investigation."""
        if investigation_id not in self.investigation_ids:
            self.investigation_ids.append(investigation_id)
            self.updated_at = datetime.utcnow()

    def merge_from(self, other: "GraphEdge") -> None:
        """Merge data from another edge (same relationship)."""
        # Merge sources
        for source in other.sources:
            self.add_source(source)

        # Merge evidence
        for ev in other.evidence:
            if ev not in self.evidence:
                self.evidence.append(ev)

        # Update timestamps
        if other.first_observed and (not self.first_observed or other.first_observed < self.first_observed):
            self.first_observed = other.first_observed
        if other.last_observed and (not self.last_observed or other.last_observed > self.last_observed):
            self.last_observed = other.last_observed

        # Merge attributes
        self.attributes.update(other.attributes)

        # Merge investigations
        for inv_id in other.investigation_ids:
            self.add_investigation(inv_id)

        # Update weight (average)
        self.weight = (self.weight + other.weight) / 2

        self.updated_at = datetime.utcnow()
        self.version += 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relationship_type": self.relationship_type.value,
            "weight": round(self.weight, 3),
            "confidence": round(self.confidence, 3),
            "composite_weight": round(self.composite_weight, 3),
            "sources": self.sources,
            "source_count": len(self.sources),
            "evidence_count": len(self.evidence),
            "first_observed": self.first_observed.isoformat() if self.first_observed else None,
            "last_observed": self.last_observed.isoformat() if self.last_observed else None,
            "active": self.active,
            "bidirectional": self.bidirectional,
            "attributes": self.attributes,
            "investigation_ids": self.investigation_ids,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "version": self.version,
        }

    def to_neo4j_properties(self) -> Dict[str, Any]:
        """Convert to Neo4j-compatible property dict."""
        return {
            "edge_id": self.edge_id,
            "relationship_type": self.relationship_type.value,
            "weight": self.weight,
            "confidence": self.confidence,
            "sources": self.sources,
            "first_observed": self.first_observed.isoformat() if self.first_observed else None,
            "last_observed": self.last_observed.isoformat() if self.last_observed else None,
            "active": self.active,
            "bidirectional": self.bidirectional,
            "investigation_ids": self.investigation_ids,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "version": self.version,
        }

    @classmethod
    def from_correlation_relationship(cls, rel: Any, investigation_id: str = None) -> "GraphEdge":
        """Create GraphEdge from correlation engine Relationship."""
        rel_type = ExtendedRelationshipType.from_string(rel.relationship_type.value)

        edge = cls(
            source_id=rel.source_entity_id,
            target_id=rel.target_entity_id,
            relationship_type=rel_type,
            confidence=rel.confidence,
            sources=rel.sources.copy(),
            first_observed=rel.first_observed,
            last_observed=rel.last_observed,
            attributes=rel.attributes.copy(),
        )

        if investigation_id:
            edge.add_investigation(investigation_id)

        return edge


# =============================================================================
# ALGORITHM RESULT MODELS
# =============================================================================

@dataclass
class CentralityScores:
    """Centrality scores for a node."""
    node_id: str
    entity_id: str
    degree: float = 0.0
    in_degree: float = 0.0
    out_degree: float = 0.0
    betweenness: float = 0.0
    closeness: float = 0.0
    eigenvector: float = 0.0
    pagerank: float = 0.0
    harmonic: float = 0.0
    katz: float = 0.0

    @property
    def composite(self) -> float:
        """Composite centrality score."""
        return (
            self.pagerank * 0.3 +
            self.betweenness * 0.3 +
            self.degree * 0.2 +
            self.eigenvector * 0.2
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "entity_id": self.entity_id,
            "degree": round(self.degree, 4),
            "in_degree": round(self.in_degree, 4),
            "out_degree": round(self.out_degree, 4),
            "betweenness": round(self.betweenness, 4),
            "closeness": round(self.closeness, 4),
            "eigenvector": round(self.eigenvector, 4),
            "pagerank": round(self.pagerank, 4),
            "harmonic": round(self.harmonic, 4),
            "katz": round(self.katz, 4),
            "composite": round(self.composite, 4),
        }


@dataclass
class CommunityInfo:
    """Community/cluster information."""
    community_id: str
    size: int
    density: float
    modularity_contribution: float
    member_ids: List[str] = field(default_factory=list)
    entity_type_distribution: Dict[str, int] = field(default_factory=dict)
    central_nodes: List[str] = field(default_factory=list)
    bridge_nodes: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "community_id": self.community_id,
            "size": self.size,
            "density": round(self.density, 3),
            "modularity_contribution": round(self.modularity_contribution, 4),
            "member_count": len(self.member_ids),
            "entity_type_distribution": self.entity_type_distribution,
            "central_nodes": self.central_nodes[:5],
            "bridge_nodes": self.bridge_nodes[:5],
            "tags": self.tags,
            "risk_score": round(self.risk_score, 1),
            "label": self.label,
        }


@dataclass
class PathResult:
    """Result of a path query."""
    found: bool
    source_id: str
    target_id: str
    path_length: int = 0
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    total_weight: float = 0.0
    total_confidence: float = 0.0
    computation_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "found": self.found,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "path_length": self.path_length,
            "nodes": self.nodes,
            "edges": self.edges,
            "total_weight": round(self.total_weight, 3),
            "total_confidence": round(self.total_confidence, 3),
            "computation_time_ms": round(self.computation_time_ms, 2),
        }


@dataclass
class SimilarityResult:
    """Similarity comparison result."""
    node_id: str
    compared_to_id: str
    jaccard_similarity: float = 0.0
    cosine_similarity: float = 0.0
    common_neighbors: int = 0
    common_neighbor_ids: List[str] = field(default_factory=list)
    shared_properties: Dict[str, Any] = field(default_factory=dict)

    @property
    def combined_similarity(self) -> float:
        """Combined similarity score."""
        return (self.jaccard_similarity + self.cosine_similarity) / 2

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "compared_to_id": self.compared_to_id,
            "jaccard_similarity": round(self.jaccard_similarity, 4),
            "cosine_similarity": round(self.cosine_similarity, 4),
            "combined_similarity": round(self.combined_similarity, 4),
            "common_neighbors": self.common_neighbors,
            "common_neighbor_ids": self.common_neighbor_ids[:10],
            "shared_properties": self.shared_properties,
        }


@dataclass
class LinkPrediction:
    """Predicted link between nodes."""
    source_id: str
    target_id: str
    predicted_relationship: ExtendedRelationshipType
    probability: float
    supporting_evidence: List[str] = field(default_factory=list)
    common_neighbors: int = 0
    adamic_adar_score: float = 0.0
    preferential_attachment_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "predicted_relationship": self.predicted_relationship.value,
            "probability": round(self.probability, 4),
            "supporting_evidence": self.supporting_evidence,
            "common_neighbors": self.common_neighbors,
            "adamic_adar_score": round(self.adamic_adar_score, 4),
            "preferential_attachment_score": round(self.preferential_attachment_score, 4),
        }


@dataclass
class AnomalyResult:
    """Graph anomaly detection result."""
    node_id: str
    anomaly_type: str  # outlier, temporal, structural, community
    anomaly_score: float
    expected_value: Optional[float] = None
    actual_value: Optional[float] = None
    description: str = ""
    related_nodes: List[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def severity(self) -> str:
        """Severity based on anomaly score."""
        if self.anomaly_score >= 0.9:
            return "critical"
        elif self.anomaly_score >= 0.7:
            return "high"
        elif self.anomaly_score >= 0.5:
            return "medium"
        return "low"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "anomaly_type": self.anomaly_type,
            "anomaly_score": round(self.anomaly_score, 4),
            "severity": self.severity,
            "expected_value": self.expected_value,
            "actual_value": self.actual_value,
            "description": self.description,
            "related_nodes": self.related_nodes[:10],
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class PropagationResult:
    """Result of influence propagation simulation."""
    seed_nodes: List[str]
    total_iterations: int
    final_infected_count: int
    infection_timeline: List[Dict[str, Any]] = field(default_factory=list)
    most_vulnerable_nodes: List[str] = field(default_factory=list)
    propagation_paths: List[List[str]] = field(default_factory=list)
    max_depth_reached: int = 0
    coverage_percentage: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seed_nodes": self.seed_nodes,
            "total_iterations": self.total_iterations,
            "final_infected_count": self.final_infected_count,
            "infection_timeline": self.infection_timeline,
            "most_vulnerable_nodes": self.most_vulnerable_nodes[:20],
            "propagation_paths_count": len(self.propagation_paths),
            "max_depth_reached": self.max_depth_reached,
            "coverage_percentage": round(self.coverage_percentage, 2),
        }


# =============================================================================
# QUERY MODELS
# =============================================================================

@dataclass
class QueryResult:
    """Result of a graph query."""
    success: bool
    query: str
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    aggregations: Dict[str, Any] = field(default_factory=dict)
    total_nodes: int = 0
    total_edges: int = 0
    execution_time_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "query": self.query,
            "nodes": self.nodes,
            "edges": self.edges,
            "aggregations": self.aggregations,
            "total_nodes": self.total_nodes,
            "total_edges": self.total_edges,
            "execution_time_ms": round(self.execution_time_ms, 2),
            "error": self.error,
        }


@dataclass
class PatternMatch:
    """Result of a pattern match."""
    pattern_name: str
    pattern_query: str
    matches: List[Dict[str, Any]] = field(default_factory=list)
    match_count: int = 0
    execution_time_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_name": self.pattern_name,
            "pattern_query": self.pattern_query,
            "matches": self.matches[:100],  # Limit for response size
            "match_count": self.match_count,
            "execution_time_ms": round(self.execution_time_ms, 2),
            "metadata": self.metadata,
        }


# =============================================================================
# VISUALIZATION MODELS
# =============================================================================

@dataclass
class VisNode:
    """Node optimized for visualization."""
    id: str
    label: str
    entity_type: str

    # Visual properties
    size: float = 10.0
    color: str = "#6B7280"
    icon: str = "circle"
    opacity: float = 1.0

    # Position
    x: Optional[float] = None
    y: Optional[float] = None
    fixed: bool = False

    # Grouping
    community_id: Optional[str] = None
    cluster_x: Optional[float] = None
    cluster_y: Optional[float] = None

    # Interaction
    tooltip: str = ""
    details_url: str = ""
    selectable: bool = True
    draggable: bool = True

    # Data
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "type": self.entity_type,
            "size": self.size,
            "color": self.color,
            "icon": self.icon,
            "opacity": self.opacity,
            "x": self.x,
            "y": self.y,
            "fixed": self.fixed,
            "community_id": self.community_id,
            "tooltip": self.tooltip,
            "data": self.data,
        }

    @classmethod
    def from_graph_node(cls, node: GraphNode, size_by: str = "centrality") -> "VisNode":
        """Create VisNode from GraphNode."""
        # Calculate size based on metric
        if size_by == "centrality":
            size = 10 + (node.centrality_score * 40)
        elif size_by == "degree":
            size = 10 + (node.total_degree * 2)
        elif size_by == "risk":
            size = 10 + (node.risk_score / 100 * 30)
        else:
            size = 15

        return cls(
            id=node.entity_id,
            label=node.label,
            entity_type=node.entity_type.value,
            size=min(50, size),
            color=node.entity_type.color,
            icon=node.entity_type.icon,
            community_id=node.community_id,
            tooltip=f"{node.entity_type.value}: {node.value}",
            data={
                "confidence": node.confidence,
                "sources": len(node.sources),
                "risk_score": node.risk_score,
                "pagerank": node.pagerank,
            },
        )


@dataclass
class VisEdge:
    """Edge optimized for visualization."""
    id: str
    source: str
    target: str
    relationship_type: str

    # Visual properties
    width: float = 1.0
    color: str = "#6B7280"
    style: str = "solid"  # solid, dashed, dotted
    opacity: float = 0.6
    curved: bool = False

    # Animation
    animated: bool = False
    animation_speed: float = 1.0

    # Labels
    label: Optional[str] = None
    tooltip: str = ""

    # Data
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "type": self.relationship_type,
            "width": self.width,
            "color": self.color,
            "style": self.style,
            "opacity": self.opacity,
            "curved": self.curved,
            "animated": self.animated,
            "label": self.label,
            "tooltip": self.tooltip,
            "data": self.data,
        }

    @classmethod
    def from_graph_edge(cls, edge: GraphEdge, width_by: str = "confidence") -> "VisEdge":
        """Create VisEdge from GraphEdge."""
        # Calculate width based on metric
        if width_by == "confidence":
            width = 1 + (edge.confidence * 4)
        elif width_by == "weight":
            width = 1 + (edge.weight * 4)
        else:
            width = 2

        # Determine style
        style = "solid"
        if edge.confidence < 0.5:
            style = "dashed"
        elif not edge.active:
            style = "dotted"

        return cls(
            id=edge.edge_id,
            source=edge.source_id,
            target=edge.target_id,
            relationship_type=edge.relationship_type.value,
            width=width,
            color=edge.relationship_type.color,
            style=style,
            animated=edge.active and edge.confidence > 0.8,
            label=edge.relationship_type.value.replace("_", " "),
            tooltip=f"{edge.relationship_type.value} (confidence: {edge.confidence:.0%})",
            data={
                "confidence": edge.confidence,
                "weight": edge.weight,
                "sources": len(edge.sources),
            },
        )


@dataclass
class GraphVisualization:
    """Complete graph visualization data."""
    nodes: List[VisNode] = field(default_factory=list)
    edges: List[VisEdge] = field(default_factory=list)

    # Layout settings
    layout_algorithm: str = "force-directed"
    layout_params: Dict[str, Any] = field(default_factory=dict)

    # Metadata
    total_nodes: int = 0
    total_edges: int = 0
    communities: List[str] = field(default_factory=list)
    entity_types: List[str] = field(default_factory=list)

    # Bounds
    min_x: float = 0.0
    max_x: float = 1000.0
    min_y: float = 0.0
    max_y: float = 1000.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "layout": {
                "algorithm": self.layout_algorithm,
                "params": self.layout_params,
            },
            "metadata": {
                "total_nodes": self.total_nodes or len(self.nodes),
                "total_edges": self.total_edges or len(self.edges),
                "communities": self.communities,
                "entity_types": self.entity_types,
            },
            "bounds": {
                "min_x": self.min_x,
                "max_x": self.max_x,
                "min_y": self.min_y,
                "max_y": self.max_y,
            },
        }


# =============================================================================
# GRAPH STATISTICS
# =============================================================================

@dataclass
class GraphStatistics:
    """Overall graph statistics."""
    total_nodes: int = 0
    total_edges: int = 0
    density: float = 0.0
    average_degree: float = 0.0
    max_degree: int = 0
    clustering_coefficient: float = 0.0
    diameter: int = 0
    average_path_length: float = 0.0
    connected_components: int = 0
    largest_component_size: int = 0

    nodes_by_type: Dict[str, int] = field(default_factory=dict)
    edges_by_type: Dict[str, int] = field(default_factory=dict)
    communities_count: int = 0
    modularity: float = 0.0

    # Temporal stats
    nodes_last_24h: int = 0
    edges_last_24h: int = 0
    nodes_last_7d: int = 0
    edges_last_7d: int = 0

    # Risk distribution
    high_risk_nodes: int = 0
    medium_risk_nodes: int = 0
    low_risk_nodes: int = 0

    computed_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_nodes": self.total_nodes,
            "total_edges": self.total_edges,
            "density": round(self.density, 4),
            "average_degree": round(self.average_degree, 2),
            "max_degree": self.max_degree,
            "clustering_coefficient": round(self.clustering_coefficient, 4),
            "diameter": self.diameter,
            "average_path_length": round(self.average_path_length, 2),
            "connected_components": self.connected_components,
            "largest_component_size": self.largest_component_size,
            "nodes_by_type": self.nodes_by_type,
            "edges_by_type": self.edges_by_type,
            "communities_count": self.communities_count,
            "modularity": round(self.modularity, 4),
            "temporal": {
                "nodes_last_24h": self.nodes_last_24h,
                "edges_last_24h": self.edges_last_24h,
                "nodes_last_7d": self.nodes_last_7d,
                "edges_last_7d": self.edges_last_7d,
            },
            "risk_distribution": {
                "high": self.high_risk_nodes,
                "medium": self.medium_risk_nodes,
                "low": self.low_risk_nodes,
            },
            "computed_at": self.computed_at.isoformat(),
        }


# =============================================================================
# HELPER CLASSES
# =============================================================================

@dataclass
class GraphConfig:
    """Configuration for graph operations."""
    # Neo4j settings
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_username: str = "neo4j"
    neo4j_password: str = ""
    neo4j_database: str = "osint_graph"

    # Cache settings
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 1
    cache_ttl_seconds: int = 300

    # Algorithm settings
    centrality_batch_size: int = 1000
    community_resolution: float = 1.0
    max_path_depth: int = 6
    max_paths_returned: int = 100

    # Visualization settings
    max_viz_nodes: int = 500
    default_layout: str = "force-directed"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "neo4j_uri": self.neo4j_uri,
            "neo4j_database": self.neo4j_database,
            "redis_host": self.redis_host,
            "redis_port": self.redis_port,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "centrality_batch_size": self.centrality_batch_size,
            "community_resolution": self.community_resolution,
            "max_path_depth": self.max_path_depth,
            "max_paths_returned": self.max_paths_returned,
            "max_viz_nodes": self.max_viz_nodes,
            "default_layout": self.default_layout,
        }


@dataclass
class GraphOperation:
    """Record of a graph operation for audit."""
    operation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    operation_type: str = ""  # create, update, delete, query, algorithm
    entity_ids: List[str] = field(default_factory=list)
    user_id: Optional[str] = None
    investigation_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"  # pending, running, completed, failed
    error: Optional[str] = None
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    execution_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "operation_type": self.operation_type,
            "entity_ids": self.entity_ids[:10],
            "entity_count": len(self.entity_ids),
            "user_id": self.user_id,
            "investigation_id": self.investigation_id,
            "status": self.status,
            "error": self.error,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "execution_time_ms": round(self.execution_time_ms, 2),
        }
