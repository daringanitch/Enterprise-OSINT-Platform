#!/usr/bin/env python3
"""
Graph Intelligence Correlation Sync

Connects existing OSINT investigations to the graph intelligence system.
Extracts entities from investigation data and builds relationships
based on correlation results.

Capabilities:
- Extract entities from investigation results
- Build relationships from correlation data
- Sync with Neo4j graph database
- Incremental updates
- Entity deduplication and merging
"""

import logging
import re
import hashlib
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import (
    ExtendedEntityType,
    ExtendedRelationshipType,
    GraphNode,
    GraphEdge,
)

logger = logging.getLogger(__name__)


# =============================================================================
# ENTITY EXTRACTION PATTERNS
# =============================================================================

ENTITY_PATTERNS = {
    ExtendedEntityType.IP_ADDRESS: [
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    ],
    ExtendedEntityType.DOMAIN: [
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
    ],
    ExtendedEntityType.EMAIL: [
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    ],
    ExtendedEntityType.URL: [
        r'https?://[^\s<>"{}|\\^`\[\]]+',
    ],
    ExtendedEntityType.HASH: [
        r'\b[A-Fa-f0-9]{32}\b',  # MD5
        r'\b[A-Fa-f0-9]{40}\b',  # SHA1
        r'\b[A-Fa-f0-9]{64}\b',  # SHA256
    ],
    ExtendedEntityType.PHONE: [
        r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
    ],
    ExtendedEntityType.CRYPTOCURRENCY_WALLET: [
        r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',  # Bitcoin
        r'\b0x[a-fA-F0-9]{40}\b',  # Ethereum
    ],
}

# Investigation field to entity type mapping
FIELD_TYPE_MAPPING = {
    'ip': ExtendedEntityType.IP_ADDRESS,
    'ip_address': ExtendedEntityType.IP_ADDRESS,
    'source_ip': ExtendedEntityType.IP_ADDRESS,
    'target_ip': ExtendedEntityType.IP_ADDRESS,
    'domain': ExtendedEntityType.DOMAIN,
    'hostname': ExtendedEntityType.DOMAIN,
    'email': ExtendedEntityType.EMAIL,
    'email_address': ExtendedEntityType.EMAIL,
    'url': ExtendedEntityType.URL,
    'hash': ExtendedEntityType.HASH,
    'md5': ExtendedEntityType.HASH,
    'sha1': ExtendedEntityType.HASH,
    'sha256': ExtendedEntityType.HASH,
    'phone': ExtendedEntityType.PHONE,
    'phone_number': ExtendedEntityType.PHONE,
    'organization': ExtendedEntityType.ORGANIZATION,
    'company': ExtendedEntityType.ORGANIZATION,
    'person': ExtendedEntityType.PERSON,
    'name': ExtendedEntityType.PERSON,
    'threat_actor': ExtendedEntityType.THREAT_ACTOR,
    'apt': ExtendedEntityType.THREAT_ACTOR,
    'malware': ExtendedEntityType.MALWARE_FAMILY,
    'malware_family': ExtendedEntityType.MALWARE_FAMILY,
    'cve': ExtendedEntityType.VULNERABILITY,
    'vulnerability': ExtendedEntityType.VULNERABILITY,
    'country': ExtendedEntityType.COUNTRY,
    'asn': ExtendedEntityType.ASN,
}


# =============================================================================
# RESULT CLASSES
# =============================================================================

@dataclass
class ExtractionResult:
    """Result of entity extraction."""
    entities_found: int
    entities_by_type: Dict[str, int] = field(default_factory=dict)
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    source_investigation: str = ""
    extraction_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entities_found": self.entities_found,
            "entities_by_type": self.entities_by_type,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "source_investigation": self.source_investigation,
            "extraction_time_ms": round(self.extraction_time_ms, 2),
        }


@dataclass
class SyncResult:
    """Result of graph synchronization."""
    nodes_created: int = 0
    nodes_updated: int = 0
    nodes_merged: int = 0
    edges_created: int = 0
    edges_updated: int = 0
    errors: List[str] = field(default_factory=list)
    sync_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes_created": self.nodes_created,
            "nodes_updated": self.nodes_updated,
            "nodes_merged": self.nodes_merged,
            "edges_created": self.edges_created,
            "edges_updated": self.edges_updated,
            "total_changes": self.nodes_created + self.nodes_updated + self.edges_created + self.edges_updated,
            "errors": self.errors[:10],
            "sync_time_ms": round(self.sync_time_ms, 2),
        }


# =============================================================================
# CORRELATION SYNC ENGINE
# =============================================================================

class CorrelationSync:
    """
    Synchronizes investigation data with the graph intelligence system.

    Extracts entities from investigation results, builds relationships,
    and syncs with the graph database.
    """

    def __init__(self, graph_client=None):
        """
        Initialize the correlation sync engine.

        Args:
            graph_client: Optional GraphClient for database access
        """
        self.graph_client = graph_client

        # Entity registry for deduplication
        self._entity_registry: Dict[str, GraphNode] = {}
        self._edge_registry: Set[Tuple[str, str, str]] = set()

        # Compile regex patterns
        self._compiled_patterns: Dict[ExtendedEntityType, List[re.Pattern]] = {}
        for entity_type, patterns in ENTITY_PATTERNS.items():
            self._compiled_patterns[entity_type] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

    # =========================================================================
    # ENTITY EXTRACTION
    # =========================================================================

    def extract_from_investigation(
        self,
        investigation_data: Dict[str, Any],
        investigation_id: str = ""
    ) -> ExtractionResult:
        """
        Extract entities and relationships from investigation data.

        Args:
            investigation_data: Investigation results dictionary
            investigation_id: Investigation identifier

        Returns:
            ExtractionResult with extracted entities and relationships
        """
        import time
        start_time = time.time()

        nodes = []
        edges = []
        entities_by_type: Dict[str, int] = defaultdict(int)

        # Process structured fields
        self._extract_from_dict(investigation_data, nodes, entities_by_type)

        # Process text content for pattern-based extraction
        text_content = self._flatten_to_text(investigation_data)
        self._extract_from_text(text_content, nodes, entities_by_type)

        # Deduplicate nodes
        unique_nodes = self._deduplicate_nodes(nodes)

        # Build relationships from co-occurrence and correlation
        edges = self._build_relationships(unique_nodes, investigation_data)

        # Tag nodes with investigation source
        for node in unique_nodes:
            if investigation_id:
                node.sources.append(investigation_id)

        extraction_time = (time.time() - start_time) * 1000

        return ExtractionResult(
            entities_found=len(unique_nodes),
            entities_by_type=dict(entities_by_type),
            nodes=unique_nodes,
            edges=edges,
            source_investigation=investigation_id,
            extraction_time_ms=extraction_time,
        )

    def _extract_from_dict(
        self,
        data: Dict[str, Any],
        nodes: List[GraphNode],
        counts: Dict[str, int],
        parent_key: str = ""
    ) -> None:
        """Recursively extract entities from dictionary structure."""
        if not isinstance(data, dict):
            return

        for key, value in data.items():
            full_key = f"{parent_key}.{key}" if parent_key else key
            key_lower = key.lower()

            # Check if key maps to entity type
            entity_type = None
            for field_name, etype in FIELD_TYPE_MAPPING.items():
                if field_name in key_lower:
                    entity_type = etype
                    break

            if entity_type and value:
                # Extract single value or list
                values = value if isinstance(value, list) else [value]
                for val in values:
                    if isinstance(val, str) and val.strip():
                        node = self._create_node(entity_type, val.strip())
                        if node:
                            nodes.append(node)
                            counts[entity_type.value] += 1

            # Recurse into nested structures
            if isinstance(value, dict):
                self._extract_from_dict(value, nodes, counts, full_key)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._extract_from_dict(item, nodes, counts, full_key)

    def _extract_from_text(
        self,
        text: str,
        nodes: List[GraphNode],
        counts: Dict[str, int]
    ) -> None:
        """Extract entities from text using regex patterns."""
        for entity_type, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                matches = pattern.findall(text)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    node = self._create_node(entity_type, match)
                    if node:
                        nodes.append(node)
                        counts[entity_type.value] += 1

    def _flatten_to_text(self, data: Any) -> str:
        """Flatten data structure to text for pattern extraction."""
        if isinstance(data, str):
            return data
        elif isinstance(data, dict):
            parts = []
            for v in data.values():
                parts.append(self._flatten_to_text(v))
            return " ".join(parts)
        elif isinstance(data, list):
            parts = []
            for item in data:
                parts.append(self._flatten_to_text(item))
            return " ".join(parts)
        else:
            return str(data) if data else ""

    def _create_node(
        self,
        entity_type: ExtendedEntityType,
        value: str
    ) -> Optional[GraphNode]:
        """Create a GraphNode from extracted value."""
        # Normalize value
        normalized = self._normalize_value(entity_type, value)
        if not normalized:
            return None

        # Generate entity ID
        entity_id = self._generate_entity_id(entity_type, normalized)

        # Check registry for existing entity
        if entity_id in self._entity_registry:
            existing = self._entity_registry[entity_id]
            existing.confidence = min(existing.confidence + 0.1, 1.0)
            return None  # Don't create duplicate

        node = GraphNode(
            entity_id=entity_id,
            entity_type=entity_type,
            value=value,
            normalized_value=normalized,
            confidence=0.7,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

        self._entity_registry[entity_id] = node
        return node

    def _normalize_value(
        self,
        entity_type: ExtendedEntityType,
        value: str
    ) -> str:
        """Normalize entity value for deduplication."""
        value = value.strip()

        if entity_type == ExtendedEntityType.DOMAIN:
            value = value.lower()
            # Remove trailing dots
            value = value.rstrip('.')
            # Remove www prefix
            if value.startswith('www.'):
                value = value[4:]

        elif entity_type == ExtendedEntityType.EMAIL:
            value = value.lower()

        elif entity_type == ExtendedEntityType.URL:
            value = value.lower()

        elif entity_type == ExtendedEntityType.HASH:
            value = value.lower()

        elif entity_type == ExtendedEntityType.IP_ADDRESS:
            # Already normalized
            pass

        return value

    def _generate_entity_id(
        self,
        entity_type: ExtendedEntityType,
        normalized_value: str
    ) -> str:
        """Generate unique entity ID."""
        content = f"{entity_type.value}:{normalized_value}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _deduplicate_nodes(self, nodes: List[GraphNode]) -> List[GraphNode]:
        """Remove duplicate nodes, keeping highest confidence."""
        seen: Dict[str, GraphNode] = {}

        for node in nodes:
            key = f"{node.entity_type.value}:{node.normalized_value or node.value}"
            if key in seen:
                existing = seen[key]
                if node.confidence > existing.confidence:
                    seen[key] = node
                else:
                    existing.confidence = min(existing.confidence + 0.05, 1.0)
            else:
                seen[key] = node

        return list(seen.values())

    # =========================================================================
    # RELATIONSHIP BUILDING
    # =========================================================================

    def _build_relationships(
        self,
        nodes: List[GraphNode],
        investigation_data: Dict[str, Any]
    ) -> List[GraphEdge]:
        """Build relationships between extracted entities."""
        edges = []

        # Build node lookup
        node_lookup = {n.entity_id: n for n in nodes}

        # Build relationships from correlation data
        correlation_data = investigation_data.get('correlation', {})
        if correlation_data:
            edges.extend(self._build_from_correlation(correlation_data, node_lookup))

        # Build relationships from MCP results
        mcp_results = investigation_data.get('mcp_results', {})
        if mcp_results:
            edges.extend(self._build_from_mcp(mcp_results, node_lookup))

        # Build co-occurrence relationships
        edges.extend(self._build_cooccurrence(nodes))

        # Deduplicate edges
        unique_edges = self._deduplicate_edges(edges)

        return unique_edges

    def _build_from_correlation(
        self,
        correlation_data: Dict[str, Any],
        node_lookup: Dict[str, GraphNode]
    ) -> List[GraphEdge]:
        """Build relationships from correlation engine output."""
        edges = []

        # Entity correlations
        entities = correlation_data.get('entities', [])
        for i, entity1 in enumerate(entities):
            for entity2 in entities[i + 1:]:
                # Create relationship if entities are related
                rel = self._infer_relationship(entity1, entity2)
                if rel:
                    edge = GraphEdge(
                        source_id=entity1.get('id', ''),
                        target_id=entity2.get('id', ''),
                        relationship_type=rel,
                        confidence=0.6,
                    )
                    edges.append(edge)

        # Explicit relationships
        relationships = correlation_data.get('relationships', [])
        for rel in relationships:
            source = rel.get('source', rel.get('from', ''))
            target = rel.get('target', rel.get('to', ''))
            rel_type = rel.get('type', 'associated_with')

            try:
                relationship_type = ExtendedRelationshipType(rel_type)
            except ValueError:
                relationship_type = ExtendedRelationshipType.ASSOCIATED_WITH

            edge = GraphEdge(
                source_id=source,
                target_id=target,
                relationship_type=relationship_type,
                confidence=rel.get('confidence', 0.7),
            )
            edges.append(edge)

        return edges

    def _build_from_mcp(
        self,
        mcp_results: Dict[str, Any],
        node_lookup: Dict[str, GraphNode]
    ) -> List[GraphEdge]:
        """Build relationships from MCP server results."""
        edges = []

        # DNS results
        dns_data = mcp_results.get('dns', {})
        if dns_data:
            domain = dns_data.get('domain', '')
            for ip in dns_data.get('a_records', []):
                edges.append(self._create_edge(
                    domain, ip,
                    ExtendedRelationshipType.RESOLVES_TO,
                    ExtendedEntityType.DOMAIN, ExtendedEntityType.IP_ADDRESS
                ))

        # WHOIS results
        whois_data = mcp_results.get('whois', {})
        if whois_data:
            domain = whois_data.get('domain', '')
            registrant = whois_data.get('registrant_email', '')
            if registrant:
                edges.append(self._create_edge(
                    domain, registrant,
                    ExtendedRelationshipType.REGISTERED_BY,
                    ExtendedEntityType.DOMAIN, ExtendedEntityType.EMAIL
                ))

        # Threat intel results
        threat_data = mcp_results.get('threat_intel', {})
        if threat_data:
            ioc = threat_data.get('indicator', '')
            for actor in threat_data.get('threat_actors', []):
                edges.append(self._create_edge(
                    ioc, actor,
                    ExtendedRelationshipType.ATTRIBUTED_TO,
                    None, ExtendedEntityType.THREAT_ACTOR
                ))

        return [e for e in edges if e is not None]

    def _build_cooccurrence(
        self,
        nodes: List[GraphNode]
    ) -> List[GraphEdge]:
        """Build co-occurrence relationships between entities."""
        edges = []

        # Group nodes by type
        by_type: Dict[ExtendedEntityType, List[GraphNode]] = defaultdict(list)
        for node in nodes:
            by_type[node.entity_type].append(node)

        # IPs co-located if in same /24
        ips = by_type.get(ExtendedEntityType.IP_ADDRESS, [])
        for i, ip1 in enumerate(ips):
            for ip2 in ips[i + 1:]:
                if self._same_subnet(ip1.value, ip2.value):
                    edges.append(GraphEdge(
                        source_id=ip1.entity_id,
                        target_id=ip2.entity_id,
                        relationship_type=ExtendedRelationshipType.COLOCATED_WITH,
                        confidence=0.8,
                    ))

        # Domains with same suffix
        domains = by_type.get(ExtendedEntityType.DOMAIN, [])
        for i, d1 in enumerate(domains):
            for d2 in domains[i + 1:]:
                if self._same_domain_family(d1.value, d2.value):
                    edges.append(GraphEdge(
                        source_id=d1.entity_id,
                        target_id=d2.entity_id,
                        relationship_type=ExtendedRelationshipType.SIMILAR_TO,
                        confidence=0.6,
                    ))

        return edges

    def _create_edge(
        self,
        source_value: str,
        target_value: str,
        relationship_type: ExtendedRelationshipType,
        source_type: Optional[ExtendedEntityType],
        target_type: Optional[ExtendedEntityType]
    ) -> Optional[GraphEdge]:
        """Create an edge between two values."""
        if not source_value or not target_value:
            return None

        # Generate IDs
        if source_type:
            source_id = self._generate_entity_id(source_type, source_value.lower())
        else:
            source_id = hashlib.sha256(source_value.encode()).hexdigest()[:16]

        if target_type:
            target_id = self._generate_entity_id(target_type, target_value.lower())
        else:
            target_id = hashlib.sha256(target_value.encode()).hexdigest()[:16]

        return GraphEdge(
            source_id=source_id,
            target_id=target_id,
            relationship_type=relationship_type,
            confidence=0.7,
        )

    def _infer_relationship(
        self,
        entity1: Dict[str, Any],
        entity2: Dict[str, Any]
    ) -> Optional[ExtendedRelationshipType]:
        """Infer relationship type between two entities."""
        type1 = entity1.get('type', '')
        type2 = entity2.get('type', '')

        # Define relationship inference rules
        rules = {
            ('domain', 'ip'): ExtendedRelationshipType.RESOLVES_TO,
            ('ip', 'domain'): ExtendedRelationshipType.HOSTS,
            ('domain', 'email'): ExtendedRelationshipType.REGISTERED_BY,
            ('malware', 'ip'): ExtendedRelationshipType.COMMUNICATES_WITH,
            ('threat_actor', 'malware'): ExtendedRelationshipType.ATTRIBUTED_TO,
            ('threat_actor', 'organization'): ExtendedRelationshipType.TARGETS,
            ('person', 'organization'): ExtendedRelationshipType.MEMBER_OF,
            ('email', 'person'): ExtendedRelationshipType.CONTROLS,
        }

        key = (type1.lower(), type2.lower())
        return rules.get(key)

    def _same_subnet(self, ip1: str, ip2: str) -> bool:
        """Check if two IPs are in the same /24 subnet."""
        try:
            parts1 = ip1.split('.')[:3]
            parts2 = ip2.split('.')[:3]
            return parts1 == parts2
        except Exception:
            return False

    def _same_domain_family(self, d1: str, d2: str) -> bool:
        """Check if two domains share a suffix."""
        try:
            # Get base domain (last two parts)
            parts1 = d1.split('.')
            parts2 = d2.split('.')
            if len(parts1) >= 2 and len(parts2) >= 2:
                return parts1[-2:] == parts2[-2:]
        except Exception:
            pass
        return False

    def _deduplicate_edges(self, edges: List[GraphEdge]) -> List[GraphEdge]:
        """Remove duplicate edges."""
        seen: Dict[Tuple[str, str, str], GraphEdge] = {}

        for edge in edges:
            key = (edge.source_id, edge.target_id, edge.relationship_type.value)
            if key in seen:
                existing = seen[key]
                if edge.confidence > existing.confidence:
                    seen[key] = edge
            else:
                seen[key] = edge

        return list(seen.values())

    # =========================================================================
    # GRAPH SYNCHRONIZATION
    # =========================================================================

    def sync_to_graph(
        self,
        nodes: List[GraphNode],
        edges: List[GraphEdge]
    ) -> SyncResult:
        """
        Sync extracted entities to the graph database.

        Args:
            nodes: List of GraphNode objects
            edges: List of GraphEdge objects

        Returns:
            SyncResult with sync statistics
        """
        import time
        start_time = time.time()

        result = SyncResult()

        if not self.graph_client:
            # Mock mode - just count operations
            result.nodes_created = len(nodes)
            result.edges_created = len(edges)
            result.sync_time_ms = (time.time() - start_time) * 1000
            return result

        try:
            # Upsert nodes
            for node in nodes:
                try:
                    existing = self.graph_client.get_node(node.entity_id)
                    if existing:
                        self.graph_client.update_node(node.entity_id, node)
                        result.nodes_updated += 1
                    else:
                        self.graph_client.create_node(node)
                        result.nodes_created += 1
                except Exception as e:
                    result.errors.append(f"Node {node.entity_id}: {str(e)}")

            # Upsert edges
            for edge in edges:
                try:
                    self.graph_client.create_edge(edge)
                    result.edges_created += 1
                except Exception as e:
                    result.errors.append(f"Edge {edge.source_id}->{edge.target_id}: {str(e)}")

        except Exception as e:
            result.errors.append(f"Sync error: {str(e)}")

        result.sync_time_ms = (time.time() - start_time) * 1000
        return result

    def sync_investigation(
        self,
        investigation_data: Dict[str, Any],
        investigation_id: str = ""
    ) -> Tuple[ExtractionResult, SyncResult]:
        """
        Full pipeline: extract entities and sync to graph.

        Args:
            investigation_data: Investigation results
            investigation_id: Investigation identifier

        Returns:
            Tuple of (ExtractionResult, SyncResult)
        """
        # Extract entities
        extraction = self.extract_from_investigation(
            investigation_data,
            investigation_id
        )

        # Sync to graph
        sync = self.sync_to_graph(extraction.nodes, extraction.edges)

        return extraction, sync

    # =========================================================================
    # BATCH OPERATIONS
    # =========================================================================

    def batch_sync_investigations(
        self,
        investigations: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Sync multiple investigations to the graph.

        Args:
            investigations: List of investigation data dictionaries

        Returns:
            Aggregated sync results
        """
        total_extraction = ExtractionResult(entities_found=0)
        total_sync = SyncResult()

        for i, inv_data in enumerate(investigations):
            inv_id = inv_data.get('id', f'inv_{i}')

            extraction, sync = self.sync_investigation(inv_data, inv_id)

            # Aggregate results
            total_extraction.entities_found += extraction.entities_found
            for etype, count in extraction.entities_by_type.items():
                total_extraction.entities_by_type[etype] = \
                    total_extraction.entities_by_type.get(etype, 0) + count

            total_sync.nodes_created += sync.nodes_created
            total_sync.nodes_updated += sync.nodes_updated
            total_sync.edges_created += sync.edges_created
            total_sync.errors.extend(sync.errors)

        return {
            'investigations_processed': len(investigations),
            'extraction': total_extraction.to_dict(),
            'sync': total_sync.to_dict(),
        }

    # =========================================================================
    # UTILITIES
    # =========================================================================

    def clear_registry(self) -> None:
        """Clear the entity registry."""
        self._entity_registry.clear()
        self._edge_registry.clear()

    def get_registry_stats(self) -> Dict[str, int]:
        """Get statistics about the entity registry."""
        type_counts: Dict[str, int] = defaultdict(int)
        for node in self._entity_registry.values():
            type_counts[node.entity_type.value] += 1

        return {
            'total_entities': len(self._entity_registry),
            'total_edges': len(self._edge_registry),
            'entities_by_type': dict(type_counts),
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def extract_entities(
    investigation_data: Dict[str, Any],
    investigation_id: str = ""
) -> ExtractionResult:
    """
    Extract entities from investigation data.

    Args:
        investigation_data: Investigation results
        investigation_id: Investigation identifier

    Returns:
        ExtractionResult with extracted entities
    """
    sync = CorrelationSync()
    return sync.extract_from_investigation(investigation_data, investigation_id)


def sync_investigation_to_graph(
    investigation_data: Dict[str, Any],
    investigation_id: str = "",
    graph_client=None
) -> Tuple[ExtractionResult, SyncResult]:
    """
    Extract and sync investigation to graph database.

    Args:
        investigation_data: Investigation results
        investigation_id: Investigation identifier
        graph_client: Optional graph database client

    Returns:
        Tuple of (ExtractionResult, SyncResult)
    """
    sync = CorrelationSync(graph_client=graph_client)
    return sync.sync_investigation(investigation_data, investigation_id)
