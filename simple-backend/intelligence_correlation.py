#!/usr/bin/env python3
"""
Intelligence Correlation Engine

Cross-source correlation, entity extraction, relationship mapping,
confidence scoring, and timeline reconstruction for OSINT investigations.
"""

import re
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any, Set, Tuple
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class EntityType(Enum):
    """Types of entities that can be extracted and correlated"""
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
    CVE = "cve"
    CRYPTOCURRENCY = "cryptocurrency"


class RelationshipType(Enum):
    """Types of relationships between entities"""
    RESOLVES_TO = "resolves_to"  # Domain -> IP
    OWNS = "owns"  # Organization -> Domain
    REGISTERED_BY = "registered_by"  # Domain -> Email/Person
    HOSTS = "hosts"  # IP -> Domain
    ASSOCIATED_WITH = "associated_with"  # Generic association
    SUBDOMAIN_OF = "subdomain_of"  # Subdomain -> Parent domain
    USES_TECHNOLOGY = "uses_technology"  # Domain -> Technology
    ISSUED_FOR = "issued_for"  # Certificate -> Domain
    MENTIONS = "mentions"  # News article -> Entity
    EXPOSED_IN = "exposed_in"  # Credential -> Breach
    MEMBER_OF = "member_of"  # Person -> Organization
    CONTROLS = "controls"  # Person -> Social account


@dataclass
class Entity:
    """Represents an extracted entity"""
    id: str
    entity_type: EntityType
    value: str
    normalized_value: str
    sources: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    confidence: float = 0.5
    attributes: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    def add_source(self, source: str):
        """Add a source and increase confidence"""
        if source not in self.sources:
            self.sources.append(source)
            # Increase confidence with each additional source (diminishing returns)
            self.confidence = min(1.0, self.confidence + (1 - self.confidence) * 0.2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'type': self.entity_type.value,
            'value': self.value,
            'normalized_value': self.normalized_value,
            'sources': self.sources,
            'source_count': len(self.sources),
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'confidence': round(self.confidence, 2),
            'attributes': self.attributes,
            'tags': self.tags
        }


@dataclass
class Relationship:
    """Represents a relationship between two entities"""
    source_entity_id: str
    target_entity_id: str
    relationship_type: RelationshipType
    confidence: float = 0.5
    sources: List[str] = field(default_factory=list)
    first_observed: Optional[datetime] = None
    last_observed: Optional[datetime] = None
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'source': self.source_entity_id,
            'target': self.target_entity_id,
            'type': self.relationship_type.value,
            'confidence': round(self.confidence, 2),
            'sources': self.sources,
            'first_observed': self.first_observed.isoformat() if self.first_observed else None,
            'last_observed': self.last_observed.isoformat() if self.last_observed else None,
            'attributes': self.attributes
        }


@dataclass
class TimelineEvent:
    """Represents an event in the investigation timeline"""
    timestamp: datetime
    event_type: str
    description: str
    entities: List[str] = field(default_factory=list)
    source: str = ""
    severity: str = "info"  # info, warning, critical
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'description': self.description,
            'entities': self.entities,
            'source': self.source,
            'severity': self.severity,
            'attributes': self.attributes
        }


@dataclass
class CorrelationResult:
    """Results of intelligence correlation"""
    entities: Dict[str, Entity] = field(default_factory=dict)
    relationships: List[Relationship] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    clusters: List[Dict[str, Any]] = field(default_factory=list)
    key_findings: List[Dict[str, Any]] = field(default_factory=list)
    confidence_summary: Dict[str, float] = field(default_factory=dict)
    statistics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'entities': {k: v.to_dict() for k, v in self.entities.items()},
            'entity_count': len(self.entities),
            'relationships': [r.to_dict() for r in self.relationships],
            'relationship_count': len(self.relationships),
            'timeline': [e.to_dict() for e in sorted(self.timeline, key=lambda x: x.timestamp)],
            'event_count': len(self.timeline),
            'clusters': self.clusters,
            'key_findings': self.key_findings,
            'confidence_summary': self.confidence_summary,
            'statistics': self.statistics
        }


class EntityExtractor:
    """Extracts entities from various data sources"""

    # Regex patterns for entity extraction
    PATTERNS = {
        EntityType.DOMAIN: re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        ),
        EntityType.IP_ADDRESS: re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ),
        EntityType.EMAIL: re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        ),
        EntityType.URL: re.compile(
            r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*'
        ),
        EntityType.HASH: re.compile(
            r'\b[a-fA-F0-9]{32,64}\b'  # MD5, SHA1, SHA256
        ),
        EntityType.PHONE: re.compile(
            r'\b(?:\+?1[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?)?[0-9]{3}[-.\s]?[0-9]{4}\b'
        ),
    }

    @classmethod
    def generate_entity_id(cls, entity_type: EntityType, value: str) -> str:
        """Generate a unique, deterministic ID for an entity"""
        normalized = cls.normalize_value(entity_type, value)
        hash_input = f"{entity_type.value}:{normalized}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]

    @classmethod
    def normalize_value(cls, entity_type: EntityType, value: str) -> str:
        """Normalize entity value for consistent matching"""
        value = value.strip()

        if entity_type == EntityType.DOMAIN:
            return value.lower().lstrip('www.')
        elif entity_type == EntityType.EMAIL:
            return value.lower()
        elif entity_type == EntityType.IP_ADDRESS:
            return value
        elif entity_type == EntityType.URL:
            return value.lower()
        elif entity_type == EntityType.HASH:
            return value.lower()
        else:
            return value

    @classmethod
    def extract_from_text(cls, text: str, source: str) -> List[Entity]:
        """Extract all entities from text"""
        entities = []

        for entity_type, pattern in cls.PATTERNS.items():
            matches = pattern.findall(text)
            for match in matches:
                normalized = cls.normalize_value(entity_type, match)
                entity_id = cls.generate_entity_id(entity_type, match)

                entity = Entity(
                    id=entity_id,
                    entity_type=entity_type,
                    value=match,
                    normalized_value=normalized,
                    sources=[source],
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow()
                )
                entities.append(entity)

        return entities

    @classmethod
    def extract_from_structured_data(cls, data: Dict[str, Any], source: str) -> List[Entity]:
        """Extract entities from structured data (e.g., API responses)"""
        entities = []

        def recursive_extract(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_path = f"{path}.{key}" if path else key

                    # Check for known entity fields
                    if key.lower() in ['domain', 'domains', 'hostname']:
                        entities.extend(cls._extract_domain_entities(value, source))
                    elif key.lower() in ['ip', 'ip_address', 'ip_addresses', 'ips']:
                        entities.extend(cls._extract_ip_entities(value, source))
                    elif key.lower() in ['email', 'emails', 'email_address']:
                        entities.extend(cls._extract_email_entities(value, source))
                    elif key.lower() in ['organization', 'org', 'company']:
                        entities.extend(cls._extract_org_entities(value, source))
                    elif key.lower() in ['registrant', 'admin', 'tech']:
                        if isinstance(value, dict):
                            entities.extend(cls._extract_contact_entities(value, source))
                    else:
                        recursive_extract(value, new_path)

            elif isinstance(obj, list):
                for item in obj:
                    recursive_extract(item, path)
            elif isinstance(obj, str):
                # Extract from string values
                entities.extend(cls.extract_from_text(obj, source))

        recursive_extract(data)
        return entities

    @classmethod
    def _extract_domain_entities(cls, value: Any, source: str) -> List[Entity]:
        entities = []
        domains = [value] if isinstance(value, str) else (value if isinstance(value, list) else [])

        for domain in domains:
            if isinstance(domain, str) and cls.PATTERNS[EntityType.DOMAIN].match(domain):
                normalized = cls.normalize_value(EntityType.DOMAIN, domain)
                entity_id = cls.generate_entity_id(EntityType.DOMAIN, domain)
                entities.append(Entity(
                    id=entity_id,
                    entity_type=EntityType.DOMAIN,
                    value=domain,
                    normalized_value=normalized,
                    sources=[source],
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow()
                ))
        return entities

    @classmethod
    def _extract_ip_entities(cls, value: Any, source: str) -> List[Entity]:
        entities = []
        ips = [value] if isinstance(value, str) else (value if isinstance(value, list) else [])

        for ip in ips:
            if isinstance(ip, str) and cls.PATTERNS[EntityType.IP_ADDRESS].match(ip):
                entity_id = cls.generate_entity_id(EntityType.IP_ADDRESS, ip)
                entities.append(Entity(
                    id=entity_id,
                    entity_type=EntityType.IP_ADDRESS,
                    value=ip,
                    normalized_value=ip,
                    sources=[source],
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow()
                ))
        return entities

    @classmethod
    def _extract_email_entities(cls, value: Any, source: str) -> List[Entity]:
        entities = []
        emails = [value] if isinstance(value, str) else (value if isinstance(value, list) else [])

        for email in emails:
            if isinstance(email, str) and cls.PATTERNS[EntityType.EMAIL].match(email):
                normalized = cls.normalize_value(EntityType.EMAIL, email)
                entity_id = cls.generate_entity_id(EntityType.EMAIL, email)
                entities.append(Entity(
                    id=entity_id,
                    entity_type=EntityType.EMAIL,
                    value=email,
                    normalized_value=normalized,
                    sources=[source],
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow()
                ))
        return entities

    @classmethod
    def _extract_org_entities(cls, value: Any, source: str) -> List[Entity]:
        entities = []
        if isinstance(value, str) and len(value) > 2:
            entity_id = cls.generate_entity_id(EntityType.ORGANIZATION, value)
            entities.append(Entity(
                id=entity_id,
                entity_type=EntityType.ORGANIZATION,
                value=value,
                normalized_value=value.strip().lower(),
                sources=[source],
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow()
            ))
        return entities

    @classmethod
    def _extract_contact_entities(cls, contact: Dict[str, Any], source: str) -> List[Entity]:
        entities = []

        if 'name' in contact and contact['name']:
            entity_id = cls.generate_entity_id(EntityType.PERSON, contact['name'])
            entities.append(Entity(
                id=entity_id,
                entity_type=EntityType.PERSON,
                value=contact['name'],
                normalized_value=contact['name'].strip().lower(),
                sources=[source],
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                attributes={k: v for k, v in contact.items() if k != 'name'}
            ))

        if 'email' in contact and contact['email']:
            entities.extend(cls._extract_email_entities(contact['email'], source))

        if 'organization' in contact and contact['organization']:
            entities.extend(cls._extract_org_entities(contact['organization'], source))

        return entities


class IntelligenceCorrelator:
    """
    Core correlation engine for OSINT intelligence

    Correlates data from multiple sources, identifies relationships,
    calculates confidence scores, and builds investigation timelines.
    """

    def __init__(self):
        self.entities: Dict[str, Entity] = {}
        self.relationships: List[Relationship] = []
        self.timeline: List[TimelineEvent] = []
        self.extractor = EntityExtractor()

    def correlate(self, investigation_data: Dict[str, Any]) -> CorrelationResult:
        """
        Perform full correlation on investigation data

        Args:
            investigation_data: Dictionary containing all collected intelligence

        Returns:
            CorrelationResult with entities, relationships, and timeline
        """
        logger.info("Starting intelligence correlation")

        # Reset state
        self.entities = {}
        self.relationships = []
        self.timeline = []

        # Extract entities from each data source
        self._extract_from_infrastructure(investigation_data.get('infrastructure', {}))
        self._extract_from_social(investigation_data.get('social', {}))
        self._extract_from_threat(investigation_data.get('threat', {}))
        self._extract_from_expanded_sources(investigation_data.get('expanded_sources', {}))

        # Build relationships
        self._build_relationships()

        # Calculate final confidence scores
        self._calculate_confidence_scores()

        # Identify clusters
        clusters = self._identify_clusters()

        # Generate key findings
        key_findings = self._generate_key_findings()

        # Build statistics
        statistics = self._build_statistics()

        result = CorrelationResult(
            entities=self.entities,
            relationships=self.relationships,
            timeline=sorted(self.timeline, key=lambda x: x.timestamp),
            clusters=clusters,
            key_findings=key_findings,
            confidence_summary=self._build_confidence_summary(),
            statistics=statistics
        )

        logger.info(f"Correlation complete: {len(self.entities)} entities, "
                   f"{len(self.relationships)} relationships, {len(self.timeline)} events")

        return result

    def _add_entity(self, entity: Entity) -> Entity:
        """Add or merge entity into the entity store"""
        if entity.id in self.entities:
            existing = self.entities[entity.id]
            for source in entity.sources:
                existing.add_source(source)
            # Update timestamps
            if entity.first_seen and (not existing.first_seen or entity.first_seen < existing.first_seen):
                existing.first_seen = entity.first_seen
            if entity.last_seen and (not existing.last_seen or entity.last_seen > existing.last_seen):
                existing.last_seen = entity.last_seen
            # Merge attributes
            existing.attributes.update(entity.attributes)
            existing.tags = list(set(existing.tags + entity.tags))
            return existing
        else:
            self.entities[entity.id] = entity
            return entity

    def _add_relationship(self, source_id: str, target_id: str,
                         rel_type: RelationshipType, source: str,
                         confidence: float = 0.5,
                         attributes: Dict[str, Any] = None):
        """Add a relationship between entities"""
        if source_id not in self.entities or target_id not in self.entities:
            return

        # Check for existing relationship
        for rel in self.relationships:
            if (rel.source_entity_id == source_id and
                rel.target_entity_id == target_id and
                rel.relationship_type == rel_type):
                if source not in rel.sources:
                    rel.sources.append(source)
                    rel.confidence = min(1.0, rel.confidence + (1 - rel.confidence) * 0.2)
                return

        relationship = Relationship(
            source_entity_id=source_id,
            target_entity_id=target_id,
            relationship_type=rel_type,
            confidence=confidence,
            sources=[source],
            first_observed=datetime.utcnow(),
            last_observed=datetime.utcnow(),
            attributes=attributes or {}
        )
        self.relationships.append(relationship)

    def _add_timeline_event(self, timestamp: datetime, event_type: str,
                           description: str, entities: List[str],
                           source: str, severity: str = "info",
                           attributes: Dict[str, Any] = None):
        """Add an event to the timeline"""
        event = TimelineEvent(
            timestamp=timestamp,
            event_type=event_type,
            description=description,
            entities=entities,
            source=source,
            severity=severity,
            attributes=attributes or {}
        )
        self.timeline.append(event)

    def _extract_from_infrastructure(self, infra_data: Dict[str, Any]):
        """Extract entities from infrastructure intelligence"""
        source = "infrastructure_intel"

        # Extract from domains
        for domain_info in infra_data.get('domains', []):
            if isinstance(domain_info, dict):
                domain = domain_info.get('domain') or domain_info.get('name', '')
            else:
                domain = str(domain_info)

            if domain:
                entity_id = EntityExtractor.generate_entity_id(EntityType.DOMAIN, domain)
                entity = Entity(
                    id=entity_id,
                    entity_type=EntityType.DOMAIN,
                    value=domain,
                    normalized_value=EntityExtractor.normalize_value(EntityType.DOMAIN, domain),
                    sources=[source],
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    attributes=domain_info if isinstance(domain_info, dict) else {}
                )
                self._add_entity(entity)

                # Add timeline event for domain discovery
                self._add_timeline_event(
                    datetime.utcnow(),
                    "domain_discovered",
                    f"Domain discovered: {domain}",
                    [entity_id],
                    source
                )

        # Extract from subdomains
        for subdomain in infra_data.get('subdomains', []):
            if subdomain:
                entity_id = EntityExtractor.generate_entity_id(EntityType.DOMAIN, subdomain)
                entity = Entity(
                    id=entity_id,
                    entity_type=EntityType.DOMAIN,
                    value=subdomain,
                    normalized_value=EntityExtractor.normalize_value(EntityType.DOMAIN, subdomain),
                    sources=[source],
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    tags=['subdomain']
                )
                self._add_entity(entity)

        # Extract from IP addresses
        for ip_info in infra_data.get('ip_addresses', []):
            if isinstance(ip_info, dict):
                ip = ip_info.get('ip') or ip_info.get('address', '')
            else:
                ip = str(ip_info)

            if ip:
                entity_id = EntityExtractor.generate_entity_id(EntityType.IP_ADDRESS, ip)
                entity = Entity(
                    id=entity_id,
                    entity_type=EntityType.IP_ADDRESS,
                    value=ip,
                    normalized_value=ip,
                    sources=[source],
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    attributes=ip_info if isinstance(ip_info, dict) else {}
                )
                self._add_entity(entity)

        # Extract from DNS records
        for record_type, records in infra_data.get('dns_records', {}).items():
            for record in records:
                if isinstance(record, dict):
                    value = record.get('value', '')
                else:
                    value = str(record)

                if EntityExtractor.PATTERNS[EntityType.IP_ADDRESS].match(value):
                    entity_id = EntityExtractor.generate_entity_id(EntityType.IP_ADDRESS, value)
                    entity = Entity(
                        id=entity_id,
                        entity_type=EntityType.IP_ADDRESS,
                        value=value,
                        normalized_value=value,
                        sources=[source],
                        first_seen=datetime.utcnow(),
                        last_seen=datetime.utcnow(),
                        tags=[f'dns_{record_type.lower()}']
                    )
                    self._add_entity(entity)

        # Extract from certificates
        for cert in infra_data.get('certificates', []):
            if isinstance(cert, dict):
                cert_id = EntityExtractor.generate_entity_id(EntityType.CERTIFICATE,
                    cert.get('fingerprint', cert.get('serial', str(cert))))
                entity = Entity(
                    id=cert_id,
                    entity_type=EntityType.CERTIFICATE,
                    value=cert.get('subject', 'Unknown'),
                    normalized_value=cert.get('subject', '').lower(),
                    sources=[source],
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    attributes=cert
                )
                self._add_entity(entity)

                # Extract domains from certificate SANs
                for san in cert.get('san', []):
                    if san:
                        san_entity_id = EntityExtractor.generate_entity_id(EntityType.DOMAIN, san)
                        san_entity = Entity(
                            id=san_entity_id,
                            entity_type=EntityType.DOMAIN,
                            value=san,
                            normalized_value=EntityExtractor.normalize_value(EntityType.DOMAIN, san),
                            sources=[source],
                            tags=['certificate_san']
                        )
                        self._add_entity(san_entity)

        # Extract from exposed services
        for service in infra_data.get('exposed_services', []):
            if isinstance(service, dict):
                port = service.get('port')
                service_name = service.get('service', service.get('name', 'unknown'))
                if service_name:
                    tech_id = EntityExtractor.generate_entity_id(EntityType.TECHNOLOGY,
                        f"{service_name}:{port}" if port else service_name)
                    entity = Entity(
                        id=tech_id,
                        entity_type=EntityType.TECHNOLOGY,
                        value=f"{service_name}" + (f":{port}" if port else ""),
                        normalized_value=service_name.lower(),
                        sources=[source],
                        first_seen=datetime.utcnow(),
                        last_seen=datetime.utcnow(),
                        attributes=service,
                        tags=['exposed_service']
                    )
                    self._add_entity(entity)

                    # Add warning event for exposed services
                    self._add_timeline_event(
                        datetime.utcnow(),
                        "service_exposed",
                        f"Exposed service detected: {service_name} on port {port}",
                        [tech_id],
                        source,
                        severity="warning"
                    )

    def _extract_from_social(self, social_data: Dict[str, Any]):
        """Extract entities from social media intelligence"""
        source = "social_intel"

        # Extract from platforms
        for platform, data in social_data.get('platforms', {}).items():
            if isinstance(data, dict):
                username = data.get('username') or data.get('handle', '')
                if username:
                    account_id = EntityExtractor.generate_entity_id(EntityType.SOCIAL_ACCOUNT,
                        f"{platform}:{username}")
                    entity = Entity(
                        id=account_id,
                        entity_type=EntityType.SOCIAL_ACCOUNT,
                        value=f"@{username} ({platform})",
                        normalized_value=f"{platform.lower()}:{username.lower()}",
                        sources=[source],
                        first_seen=datetime.utcnow(),
                        last_seen=datetime.utcnow(),
                        attributes=data,
                        tags=[platform.lower()]
                    )
                    self._add_entity(entity)

                # Extract any URLs, emails from profile data
                profile_text = str(data.get('bio', '')) + str(data.get('description', ''))
                if profile_text:
                    extracted = EntityExtractor.extract_from_text(profile_text, source)
                    for e in extracted:
                        self._add_entity(e)

    def _extract_from_threat(self, threat_data: Dict[str, Any]):
        """Extract entities from threat intelligence"""
        source = "threat_intel"

        # Extract from malware indicators
        for indicator in threat_data.get('malware_indicators', []):
            if isinstance(indicator, dict):
                ioc_type = indicator.get('type', '').lower()
                ioc_value = indicator.get('value', '')

                if 'hash' in ioc_type or 'md5' in ioc_type or 'sha' in ioc_type:
                    entity_id = EntityExtractor.generate_entity_id(EntityType.HASH, ioc_value)
                    entity = Entity(
                        id=entity_id,
                        entity_type=EntityType.HASH,
                        value=ioc_value,
                        normalized_value=ioc_value.lower(),
                        sources=[source],
                        first_seen=datetime.utcnow(),
                        last_seen=datetime.utcnow(),
                        attributes=indicator,
                        tags=['malware_indicator']
                    )
                    self._add_entity(entity)

                    self._add_timeline_event(
                        datetime.utcnow(),
                        "malware_indicator_found",
                        f"Malware indicator detected: {ioc_value[:16]}...",
                        [entity_id],
                        source,
                        severity="critical"
                    )

        # Extract from network indicators
        for indicator in threat_data.get('network_indicators', []):
            if isinstance(indicator, dict):
                # Extract IPs and domains
                entities = EntityExtractor.extract_from_structured_data(indicator, source)
                for entity in entities:
                    entity.tags.append('threat_indicator')
                    self._add_entity(entity)

        # Extract threat actors
        for actor in threat_data.get('threat_actors', []):
            if isinstance(actor, dict):
                name = actor.get('name', '')
                if name:
                    actor_id = EntityExtractor.generate_entity_id(EntityType.ORGANIZATION,
                        f"threat_actor:{name}")
                    entity = Entity(
                        id=actor_id,
                        entity_type=EntityType.ORGANIZATION,
                        value=name,
                        normalized_value=name.lower(),
                        sources=[source],
                        first_seen=datetime.utcnow(),
                        last_seen=datetime.utcnow(),
                        attributes=actor,
                        tags=['threat_actor']
                    )
                    self._add_entity(entity)

    def _extract_from_expanded_sources(self, expanded_data: Dict[str, Any]):
        """Extract entities from expanded data sources"""

        # Passive DNS
        passive_dns = expanded_data.get('passive_dns', {})
        if isinstance(passive_dns, dict) and passive_dns.get('success'):
            data = passive_dns.get('data', {})
            source = "passive_dns"

            for record in data.get('historical_dns', []):
                if isinstance(record, dict):
                    ip = record.get('ip')
                    if ip:
                        entity_id = EntityExtractor.generate_entity_id(EntityType.IP_ADDRESS, ip)
                        first_seen = None
                        if record.get('first_seen'):
                            try:
                                first_seen = datetime.strptime(record['first_seen'], '%Y-%m-%d')
                            except:
                                pass

                        entity = Entity(
                            id=entity_id,
                            entity_type=EntityType.IP_ADDRESS,
                            value=ip,
                            normalized_value=ip,
                            sources=[source],
                            first_seen=first_seen,
                            last_seen=datetime.utcnow(),
                            attributes={'organizations': record.get('organizations', [])},
                            tags=['historical_dns']
                        )
                        self._add_entity(entity)

                        if first_seen:
                            self._add_timeline_event(
                                first_seen,
                                "dns_resolution",
                                f"Domain resolved to IP: {ip}",
                                [entity_id],
                                source
                            )

            for subdomain in data.get('subdomains', []):
                if subdomain:
                    entity_id = EntityExtractor.generate_entity_id(EntityType.DOMAIN, subdomain)
                    entity = Entity(
                        id=entity_id,
                        entity_type=EntityType.DOMAIN,
                        value=subdomain,
                        normalized_value=EntityExtractor.normalize_value(EntityType.DOMAIN, subdomain),
                        sources=[source],
                        tags=['passive_dns_subdomain']
                    )
                    self._add_entity(entity)

        # Breach Intelligence
        breach_intel = expanded_data.get('breach_intel', {})
        if isinstance(breach_intel, dict) and breach_intel.get('success'):
            data = breach_intel.get('data', {})
            source = "breach_intel"

            for breach in data.get('breaches', []):
                if isinstance(breach, dict):
                    breach_name = breach.get('name', 'Unknown breach')
                    breach_date = breach.get('date')

                    if breach_date:
                        try:
                            event_date = datetime.strptime(breach_date, '%Y-%m-%d')
                        except:
                            event_date = datetime.utcnow()

                        self._add_timeline_event(
                            event_date,
                            "data_breach",
                            f"Data breach: {breach_name} - {breach.get('records', 0):,} records exposed",
                            [],
                            source,
                            severity="critical",
                            attributes=breach
                        )

        # Code Intelligence
        code_intel = expanded_data.get('code_intel', {})
        if isinstance(code_intel, dict) and code_intel.get('success'):
            data = code_intel.get('data', {})
            source = "code_intel"

            for repo in data.get('repositories', []):
                if isinstance(repo, dict):
                    repo_url = repo.get('url', '')
                    if repo_url:
                        entity_id = EntityExtractor.generate_entity_id(EntityType.URL, repo_url)
                        entity = Entity(
                            id=entity_id,
                            entity_type=EntityType.URL,
                            value=repo_url,
                            normalized_value=repo_url.lower(),
                            sources=[source],
                            attributes=repo,
                            tags=['code_repository']
                        )
                        self._add_entity(entity)

            for exposure in data.get('potential_exposures', []):
                if isinstance(exposure, dict):
                    self._add_timeline_event(
                        datetime.utcnow(),
                        "code_exposure",
                        f"Potential code exposure: {exposure.get('type', 'unknown')}",
                        [],
                        source,
                        severity="warning",
                        attributes=exposure
                    )

        # URL Intelligence
        url_intel = expanded_data.get('url_intel', {})
        if isinstance(url_intel, dict) and url_intel.get('success'):
            data = url_intel.get('data', {})
            source = "url_intel"

            for mal_url in data.get('malicious_urls', []):
                if isinstance(mal_url, dict):
                    url = mal_url.get('url', '')
                    if url:
                        entity_id = EntityExtractor.generate_entity_id(EntityType.URL, url)
                        entity = Entity(
                            id=entity_id,
                            entity_type=EntityType.URL,
                            value=url,
                            normalized_value=url.lower(),
                            sources=[source],
                            attributes=mal_url,
                            tags=['malicious_url', mal_url.get('threat_type', 'unknown')]
                        )
                        self._add_entity(entity)

                        self._add_timeline_event(
                            datetime.utcnow(),
                            "malicious_url_found",
                            f"Malicious URL detected: {url[:50]}...",
                            [entity_id],
                            source,
                            severity="critical"
                        )

        # Business Intelligence
        business_intel = expanded_data.get('business_intel', {})
        if isinstance(business_intel, dict) and business_intel.get('success'):
            data = business_intel.get('data', {})
            source = "business_intel"

            company_info = data.get('company_info', {})
            if company_info:
                company_name = company_info.get('name', '')
                if company_name:
                    entity_id = EntityExtractor.generate_entity_id(EntityType.ORGANIZATION, company_name)
                    entity = Entity(
                        id=entity_id,
                        entity_type=EntityType.ORGANIZATION,
                        value=company_name,
                        normalized_value=company_name.lower(),
                        sources=[source],
                        attributes=company_info,
                        tags=['target_company']
                    )
                    self._add_entity(entity)

        # News Intelligence
        news_intel = expanded_data.get('news_intel', {})
        if isinstance(news_intel, dict) and news_intel.get('success'):
            data = news_intel.get('data', {})
            source = "news_intel"

            for article in data.get('articles', []):
                if isinstance(article, dict):
                    published = article.get('published_at')
                    if published:
                        try:
                            event_date = datetime.strptime(published[:10], '%Y-%m-%d')
                        except:
                            event_date = datetime.utcnow()

                        sentiment = article.get('sentiment', 'neutral')
                        severity = "info"
                        if sentiment == 'negative':
                            severity = "warning"

                        self._add_timeline_event(
                            event_date,
                            "news_mention",
                            f"News: {article.get('title', 'Unknown')}",
                            [],
                            source,
                            severity=severity,
                            attributes=article
                        )

    def _build_relationships(self):
        """Build relationships between discovered entities"""
        domains = [e for e in self.entities.values() if e.entity_type == EntityType.DOMAIN]
        ips = [e for e in self.entities.values() if e.entity_type == EntityType.IP_ADDRESS]
        organizations = [e for e in self.entities.values() if e.entity_type == EntityType.ORGANIZATION]
        emails = [e for e in self.entities.values() if e.entity_type == EntityType.EMAIL]
        certificates = [e for e in self.entities.values() if e.entity_type == EntityType.CERTIFICATE]

        # Domain -> IP relationships (from historical DNS and passive DNS)
        for domain in domains:
            for ip in ips:
                # Check if they share sources (co-occurrence indicates relationship)
                shared_sources = set(domain.sources) & set(ip.sources)
                if shared_sources:
                    self._add_relationship(
                        domain.id, ip.id,
                        RelationshipType.RESOLVES_TO,
                        list(shared_sources)[0],
                        confidence=0.7
                    )

        # Subdomain -> Parent domain relationships
        for subdomain in [d for d in domains if 'subdomain' in d.tags or 'passive_dns_subdomain' in d.tags]:
            parts = subdomain.normalized_value.split('.')
            if len(parts) > 2:
                parent = '.'.join(parts[-2:])
                parent_id = EntityExtractor.generate_entity_id(EntityType.DOMAIN, parent)
                if parent_id in self.entities:
                    self._add_relationship(
                        subdomain.id, parent_id,
                        RelationshipType.SUBDOMAIN_OF,
                        subdomain.sources[0] if subdomain.sources else "inferred",
                        confidence=0.95
                    )

        # Certificate -> Domain relationships
        for cert in certificates:
            for domain in domains:
                # Check SANs in certificate attributes
                sans = cert.attributes.get('san', [])
                if domain.normalized_value in [s.lower().lstrip('*.') for s in sans]:
                    self._add_relationship(
                        cert.id, domain.id,
                        RelationshipType.ISSUED_FOR,
                        "infrastructure_intel",
                        confidence=0.9
                    )

        # Organization -> Domain relationships (inferred from WHOIS, etc.)
        for org in organizations:
            for domain in domains:
                # Check if organization is mentioned in domain attributes
                registrant = domain.attributes.get('registrant', {})
                if isinstance(registrant, dict):
                    registrant_org = registrant.get('organization', '').lower()
                    if registrant_org and org.normalized_value in registrant_org:
                        self._add_relationship(
                            org.id, domain.id,
                            RelationshipType.OWNS,
                            "infrastructure_intel",
                            confidence=0.8
                        )

        # Email -> Domain relationships (email domain matches)
        for email in emails:
            email_domain = email.normalized_value.split('@')[-1]
            domain_id = EntityExtractor.generate_entity_id(EntityType.DOMAIN, email_domain)
            if domain_id in self.entities:
                self._add_relationship(
                    email.id, domain_id,
                    RelationshipType.ASSOCIATED_WITH,
                    email.sources[0] if email.sources else "inferred",
                    confidence=0.85
                )

    def _calculate_confidence_scores(self):
        """Calculate final confidence scores based on multi-source confirmation"""
        for entity in self.entities.values():
            # Base confidence from number of sources
            source_factor = min(1.0, len(entity.sources) * 0.2)

            # Relationship factor (entities with more relationships are more confirmed)
            rel_count = sum(1 for r in self.relationships
                          if r.source_entity_id == entity.id or r.target_entity_id == entity.id)
            rel_factor = min(1.0, rel_count * 0.1)

            # Final confidence
            entity.confidence = min(1.0, (entity.confidence + source_factor + rel_factor) / 2)

    def _identify_clusters(self) -> List[Dict[str, Any]]:
        """Identify clusters of related entities"""
        clusters = []
        visited = set()

        def dfs(entity_id: str, cluster: Set[str]):
            if entity_id in visited:
                return
            visited.add(entity_id)
            cluster.add(entity_id)

            for rel in self.relationships:
                if rel.source_entity_id == entity_id and rel.target_entity_id not in visited:
                    dfs(rel.target_entity_id, cluster)
                elif rel.target_entity_id == entity_id and rel.source_entity_id not in visited:
                    dfs(rel.source_entity_id, cluster)

        for entity_id in self.entities:
            if entity_id not in visited:
                cluster = set()
                dfs(entity_id, cluster)
                if len(cluster) > 1:
                    cluster_entities = [self.entities[eid].to_dict() for eid in cluster]
                    clusters.append({
                        'size': len(cluster),
                        'entity_ids': list(cluster),
                        'entity_types': list(set(e['type'] for e in cluster_entities)),
                        'total_sources': len(set(s for e in cluster_entities for s in e['sources']))
                    })

        return sorted(clusters, key=lambda x: x['size'], reverse=True)

    def _generate_key_findings(self) -> List[Dict[str, Any]]:
        """Generate key findings from correlation analysis"""
        findings = []

        # High confidence entities confirmed by multiple sources
        multi_source_entities = [e for e in self.entities.values() if len(e.sources) >= 3]
        if multi_source_entities:
            findings.append({
                'type': 'multi_source_confirmation',
                'severity': 'info',
                'title': 'Entities Confirmed by Multiple Sources',
                'description': f"{len(multi_source_entities)} entities were confirmed by 3+ independent sources",
                'entities': [e.id for e in multi_source_entities[:5]]
            })

        # Critical events in timeline
        critical_events = [e for e in self.timeline if e.severity == 'critical']
        if critical_events:
            findings.append({
                'type': 'critical_events',
                'severity': 'critical',
                'title': 'Critical Security Events Detected',
                'description': f"{len(critical_events)} critical events found in timeline",
                'events': [e.to_dict() for e in critical_events[:5]]
            })

        # Threat indicators
        threat_entities = [e for e in self.entities.values()
                         if 'threat_indicator' in e.tags or 'malware_indicator' in e.tags]
        if threat_entities:
            findings.append({
                'type': 'threat_indicators',
                'severity': 'high',
                'title': 'Threat Indicators Identified',
                'description': f"{len(threat_entities)} potential threat indicators discovered",
                'entities': [e.id for e in threat_entities[:5]]
            })

        # Data breaches
        breach_events = [e for e in self.timeline if e.event_type == 'data_breach']
        if breach_events:
            findings.append({
                'type': 'data_breaches',
                'severity': 'high',
                'title': 'Historical Data Breaches',
                'description': f"{len(breach_events)} data breaches associated with target",
                'events': [e.to_dict() for e in breach_events]
            })

        # Exposed services
        exposed_services = [e for e in self.entities.values()
                          if e.entity_type == EntityType.TECHNOLOGY and 'exposed_service' in e.tags]
        if exposed_services:
            findings.append({
                'type': 'exposed_services',
                'severity': 'warning',
                'title': 'Exposed Network Services',
                'description': f"{len(exposed_services)} potentially exposed services detected",
                'entities': [e.id for e in exposed_services]
            })

        return findings

    def ingest_nlp_result(self, nlp_result: Any, source: str = "nlp") -> int:
        """
        Convert a :class:`~nlp_pipeline.NLPResult` (or its ``to_dict()``
        representation) to :class:`Entity` objects and add them to
        ``self.entities``.

        Returns the count of *new* entities added (duplicates are merged into
        existing entities via :meth:`_add_entity`).
        """
        import hashlib
        from datetime import datetime, timezone

        def _make_id(entity_type_value: str, value: str) -> str:
            key = f"{entity_type_value}:{value.lower()}"
            return hashlib.md5(key.encode()).hexdigest()[:16]

        # Support both NLPResult dataclass instances and to_dict() output
        if hasattr(nlp_result, "to_dict"):
            data = nlp_result.to_dict()
        else:
            data = dict(nlp_result)

        added = 0
        now = datetime.now(tz=timezone.utc)

        type_map = [
            ("cves",              EntityType.CVE,           0.95),
            ("bitcoin_addresses", EntityType.CRYPTOCURRENCY, 0.90),
            ("ethereum_addresses",EntityType.CRYPTOCURRENCY, 0.90),
            ("onion_domains",     EntityType.DOMAIN,        0.95),
            ("organizations",     EntityType.ORGANIZATION,  0.75),
            ("persons",           EntityType.PERSON,        0.70),
        ]

        for field_name, entity_type, confidence in type_map:
            for value in data.get(field_name, []):
                if not value:
                    continue
                entity_id = _make_id(entity_type.value, value)
                entity = Entity(
                    id=entity_id,
                    entity_type=entity_type,
                    value=value,
                    normalized_value=value.lower(),
                    sources=[source],
                    first_seen=now,
                    last_seen=now,
                    confidence=confidence,
                    attributes={
                        "nlp_field": field_name,
                        "currency": "BTC" if field_name == "bitcoin_addresses"
                                    else "ETH" if field_name == "ethereum_addresses"
                                    else None,
                    },
                )
                before = len(self.entities)
                self._add_entity(entity)
                if len(self.entities) > before:
                    added += 1

        # Threat actors → ORGANIZATION with is_threat_actor flag
        for actor in data.get("threat_actors", []):
            if not actor:
                continue
            entity_id = _make_id(EntityType.ORGANIZATION.value, actor)
            entity = Entity(
                id=entity_id,
                entity_type=EntityType.ORGANIZATION,
                value=actor,
                normalized_value=actor.lower(),
                sources=[source],
                first_seen=now,
                last_seen=now,
                confidence=0.85,
                attributes={"is_threat_actor": True},
                tags=["threat-actor"],
            )
            before = len(self.entities)
            self._add_entity(entity)
            if len(self.entities) > before:
                added += 1

        logger.info(
            "ingest_nlp_result: added %d new entities from source='%s'",
            added,
            source,
        )
        return added

    def _build_confidence_summary(self) -> Dict[str, float]:
        """Build summary of confidence scores by entity type"""
        summary = {}

        for entity_type in EntityType:
            entities = [e for e in self.entities.values() if e.entity_type == entity_type]
            if entities:
                avg_confidence = sum(e.confidence for e in entities) / len(entities)
                summary[entity_type.value] = round(avg_confidence, 2)

        if self.entities:
            summary['overall'] = round(
                sum(e.confidence for e in self.entities.values()) / len(self.entities), 2
            )

        return summary

    def _build_statistics(self) -> Dict[str, Any]:
        """Build correlation statistics"""
        entity_by_type = defaultdict(int)
        for entity in self.entities.values():
            entity_by_type[entity.entity_type.value] += 1

        rel_by_type = defaultdict(int)
        for rel in self.relationships:
            rel_by_type[rel.relationship_type.value] += 1

        event_by_severity = defaultdict(int)
        for event in self.timeline:
            event_by_severity[event.severity] += 1

        sources = set()
        for entity in self.entities.values():
            sources.update(entity.sources)

        return {
            'total_entities': len(self.entities),
            'entities_by_type': dict(entity_by_type),
            'total_relationships': len(self.relationships),
            'relationships_by_type': dict(rel_by_type),
            'total_timeline_events': len(self.timeline),
            'events_by_severity': dict(event_by_severity),
            'unique_sources': len(sources),
            'source_list': list(sources)
        }


# Global correlator instance
intelligence_correlator = IntelligenceCorrelator()
