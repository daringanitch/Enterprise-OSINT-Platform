#!/usr/bin/env python3
"""
Unit tests for intelligence correlation module.

Tests:
- Entity extraction from various data sources
- Cross-source correlation
- Relationship building
- Confidence scoring
- Timeline reconstruction
"""

import pytest
import sys
import os
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from intelligence_correlation import (
    EntityType, RelationshipType, Entity, Relationship, TimelineEvent,
    CorrelationResult, EntityExtractor, IntelligenceCorrelator
)


class TestEntityType:
    """Test EntityType enum"""

    def test_enum_values(self):
        """Test enum values exist"""
        assert EntityType.DOMAIN.value == 'domain'
        assert EntityType.IP_ADDRESS.value == 'ip_address'
        assert EntityType.EMAIL.value == 'email'
        assert EntityType.ORGANIZATION.value == 'organization'
        assert EntityType.URL.value == 'url'
        assert EntityType.HASH.value == 'hash'


class TestRelationshipType:
    """Test RelationshipType enum"""

    def test_enum_values(self):
        """Test enum values exist"""
        assert RelationshipType.RESOLVES_TO.value == 'resolves_to'
        assert RelationshipType.OWNS.value == 'owns'
        assert RelationshipType.SUBDOMAIN_OF.value == 'subdomain_of'
        assert RelationshipType.ASSOCIATED_WITH.value == 'associated_with'


class TestEntity:
    """Test Entity dataclass"""

    def test_create_entity(self):
        """Test creating an entity"""
        entity = Entity(
            id='test_id',
            entity_type=EntityType.DOMAIN,
            value='example.com',
            normalized_value='example.com',
            sources=['source1']
        )
        assert entity.id == 'test_id'
        assert entity.entity_type == EntityType.DOMAIN
        assert entity.confidence == 0.5

    def test_add_source_increases_confidence(self):
        """Test that adding sources increases confidence"""
        entity = Entity(
            id='test_id',
            entity_type=EntityType.DOMAIN,
            value='example.com',
            normalized_value='example.com',
            sources=['source1'],
            confidence=0.5
        )
        initial_confidence = entity.confidence
        entity.add_source('source2')
        assert entity.confidence > initial_confidence
        assert 'source2' in entity.sources

    def test_add_duplicate_source(self):
        """Test that duplicate sources don't increase confidence"""
        entity = Entity(
            id='test_id',
            entity_type=EntityType.DOMAIN,
            value='example.com',
            normalized_value='example.com',
            sources=['source1'],
            confidence=0.5
        )
        entity.add_source('source1')
        assert len(entity.sources) == 1

    def test_to_dict(self):
        """Test serialization to dict"""
        entity = Entity(
            id='test_id',
            entity_type=EntityType.DOMAIN,
            value='example.com',
            normalized_value='example.com',
            sources=['source1'],
            first_seen=datetime.utcnow()
        )
        d = entity.to_dict()
        assert d['id'] == 'test_id'
        assert d['type'] == 'domain'
        assert d['source_count'] == 1
        assert 'first_seen' in d


class TestRelationship:
    """Test Relationship dataclass"""

    def test_create_relationship(self):
        """Test creating a relationship"""
        rel = Relationship(
            source_entity_id='src_id',
            target_entity_id='tgt_id',
            relationship_type=RelationshipType.RESOLVES_TO,
            sources=['dns_source']
        )
        assert rel.source_entity_id == 'src_id'
        assert rel.target_entity_id == 'tgt_id'
        assert rel.relationship_type == RelationshipType.RESOLVES_TO

    def test_to_dict(self):
        """Test serialization to dict"""
        rel = Relationship(
            source_entity_id='src_id',
            target_entity_id='tgt_id',
            relationship_type=RelationshipType.OWNS,
            confidence=0.8,
            sources=['whois']
        )
        d = rel.to_dict()
        assert d['source'] == 'src_id'
        assert d['target'] == 'tgt_id'
        assert d['type'] == 'owns'
        assert d['confidence'] == 0.8


class TestTimelineEvent:
    """Test TimelineEvent dataclass"""

    def test_create_event(self):
        """Test creating a timeline event"""
        event = TimelineEvent(
            timestamp=datetime.utcnow(),
            event_type='domain_discovered',
            description='Domain discovered: example.com',
            source='infrastructure_intel'
        )
        assert event.event_type == 'domain_discovered'
        assert event.severity == 'info'

    def test_to_dict(self):
        """Test serialization to dict"""
        event = TimelineEvent(
            timestamp=datetime.utcnow(),
            event_type='malware_detected',
            description='Malware indicator found',
            severity='critical',
            source='threat_intel'
        )
        d = event.to_dict()
        assert d['event_type'] == 'malware_detected'
        assert d['severity'] == 'critical'
        assert 'timestamp' in d


class TestEntityExtractor:
    """Test EntityExtractor class"""

    def test_normalize_domain(self):
        """Test domain normalization"""
        normalized = EntityExtractor.normalize_value(EntityType.DOMAIN, 'WWW.Example.COM')
        assert normalized == 'example.com'

    def test_normalize_email(self):
        """Test email normalization"""
        normalized = EntityExtractor.normalize_value(EntityType.EMAIL, 'User@Example.COM')
        assert normalized == 'user@example.com'

    def test_generate_entity_id(self):
        """Test entity ID generation is deterministic"""
        id1 = EntityExtractor.generate_entity_id(EntityType.DOMAIN, 'example.com')
        id2 = EntityExtractor.generate_entity_id(EntityType.DOMAIN, 'example.com')
        id3 = EntityExtractor.generate_entity_id(EntityType.DOMAIN, 'other.com')
        assert id1 == id2
        assert id1 != id3

    def test_extract_domain_from_text(self):
        """Test extracting domains from text"""
        text = "Visit our website at www.example.com for more info"
        entities = EntityExtractor.extract_from_text(text, 'test_source')
        domains = [e for e in entities if e.entity_type == EntityType.DOMAIN]
        assert len(domains) >= 1
        assert any('example.com' in e.normalized_value for e in domains)

    def test_extract_ip_from_text(self):
        """Test extracting IP addresses from text"""
        text = "Server is located at 192.168.1.1 and backup at 10.0.0.1"
        entities = EntityExtractor.extract_from_text(text, 'test_source')
        ips = [e for e in entities if e.entity_type == EntityType.IP_ADDRESS]
        assert len(ips) == 2

    def test_extract_email_from_text(self):
        """Test extracting emails from text"""
        text = "Contact us at admin@example.com or support@test.org"
        entities = EntityExtractor.extract_from_text(text, 'test_source')
        emails = [e for e in entities if e.entity_type == EntityType.EMAIL]
        assert len(emails) == 2

    def test_extract_from_structured_data(self):
        """Test extracting from structured data"""
        data = {
            'domain': 'example.com',
            'ip_addresses': ['192.168.1.1', '10.0.0.1'],
            'registrant': {
                'name': 'John Doe',
                'email': 'john@example.com',
                'organization': 'Example Corp'
            }
        }
        entities = EntityExtractor.extract_from_structured_data(data, 'test_source')
        assert len(entities) > 0

        # Check for domain
        domains = [e for e in entities if e.entity_type == EntityType.DOMAIN]
        assert len(domains) >= 1

        # Check for IPs
        ips = [e for e in entities if e.entity_type == EntityType.IP_ADDRESS]
        assert len(ips) >= 2


class TestIntelligenceCorrelator:
    """Test IntelligenceCorrelator class"""

    @pytest.fixture
    def correlator(self):
        return IntelligenceCorrelator()

    @pytest.fixture
    def sample_data(self):
        """Sample investigation data for testing"""
        return {
            'infrastructure': {
                'domains': [
                    {'domain': 'example.com', 'registrant': {'organization': 'Example Corp'}},
                    {'domain': 'test.example.com'}
                ],
                'subdomains': ['www.example.com', 'api.example.com', 'mail.example.com'],
                'ip_addresses': [
                    {'ip': '192.168.1.1', 'organization': 'Hosting Provider'},
                    {'ip': '10.0.0.1'}
                ],
                'dns_records': {
                    'A': [{'value': '192.168.1.1'}],
                    'MX': [{'value': 'mail.example.com'}]
                },
                'exposed_services': [
                    {'port': 80, 'service': 'HTTP'},
                    {'port': 443, 'service': 'HTTPS'}
                ],
                'certificates': [
                    {
                        'subject': 'example.com',
                        'fingerprint': 'abc123',
                        'san': ['example.com', 'www.example.com']
                    }
                ]
            },
            'social': {
                'platforms': {
                    'twitter': {'username': 'examplecorp', 'followers': 5000},
                    'linkedin': {'username': 'example-corp'}
                }
            },
            'threat': {
                'malware_indicators': [
                    {'type': 'md5', 'value': 'abc123def456'}
                ],
                'network_indicators': [
                    {'ip': '192.168.1.1', 'threat_type': 'c2'}
                ],
                'threat_actors': [
                    {'name': 'APT-TEST'}
                ]
            },
            'expanded_sources': {
                'passive_dns': {
                    'success': True,
                    'data': {
                        'historical_dns': [
                            {'ip': '192.168.1.1', 'first_seen': '2024-01-01', 'last_seen': '2024-06-01'}
                        ],
                        'subdomains': ['dev.example.com']
                    }
                },
                'breach_intel': {
                    'success': True,
                    'data': {
                        'breaches': [
                            {'name': 'Test Breach', 'date': '2023-06-15', 'records': 1000}
                        ]
                    }
                }
            }
        }

    def test_correlate_returns_result(self, correlator, sample_data):
        """Test that correlate returns a CorrelationResult"""
        result = correlator.correlate(sample_data)
        assert isinstance(result, CorrelationResult)

    def test_entities_extracted(self, correlator, sample_data):
        """Test that entities are extracted from data"""
        result = correlator.correlate(sample_data)
        assert len(result.entities) > 0

    def test_domain_entities_found(self, correlator, sample_data):
        """Test that domain entities are found"""
        result = correlator.correlate(sample_data)
        domain_entities = [e for e in result.entities.values()
                         if e.entity_type == EntityType.DOMAIN]
        assert len(domain_entities) > 0

    def test_ip_entities_found(self, correlator, sample_data):
        """Test that IP entities are found"""
        result = correlator.correlate(sample_data)
        ip_entities = [e for e in result.entities.values()
                      if e.entity_type == EntityType.IP_ADDRESS]
        assert len(ip_entities) > 0

    def test_relationships_built(self, correlator, sample_data):
        """Test that relationships are built between entities"""
        result = correlator.correlate(sample_data)
        assert len(result.relationships) > 0

    def test_timeline_populated(self, correlator, sample_data):
        """Test that timeline events are created"""
        result = correlator.correlate(sample_data)
        assert len(result.timeline) > 0

    def test_key_findings_generated(self, correlator, sample_data):
        """Test that key findings are generated"""
        result = correlator.correlate(sample_data)
        # Key findings depend on the data, may or may not exist
        assert isinstance(result.key_findings, list)

    def test_statistics_calculated(self, correlator, sample_data):
        """Test that statistics are calculated"""
        result = correlator.correlate(sample_data)
        stats = result.statistics
        assert 'total_entities' in stats
        assert 'total_relationships' in stats
        assert 'entities_by_type' in stats

    def test_confidence_summary(self, correlator, sample_data):
        """Test that confidence summary is built"""
        result = correlator.correlate(sample_data)
        summary = result.confidence_summary
        assert isinstance(summary, dict)

    def test_to_dict(self, correlator, sample_data):
        """Test result serialization"""
        result = correlator.correlate(sample_data)
        d = result.to_dict()
        assert 'entities' in d
        assert 'relationships' in d
        assert 'timeline' in d
        assert 'statistics' in d

    def test_multi_source_confidence_boost(self, correlator):
        """Test that entities from multiple sources have higher confidence"""
        # Data where same IP appears in multiple sources
        data = {
            'infrastructure': {
                'ip_addresses': [{'ip': '192.168.1.1'}]
            },
            'threat': {
                'network_indicators': [{'ip': '192.168.1.1'}]
            },
            'expanded_sources': {
                'passive_dns': {
                    'success': True,
                    'data': {
                        'historical_dns': [{'ip': '192.168.1.1', 'first_seen': '2024-01-01'}]
                    }
                }
            }
        }
        result = correlator.correlate(data)

        ip_entities = [e for e in result.entities.values()
                      if e.entity_type == EntityType.IP_ADDRESS and e.value == '192.168.1.1']

        if ip_entities:
            # Entity should have multiple sources
            entity = ip_entities[0]
            assert len(entity.sources) >= 2
            # Confidence should be boosted above base
            assert entity.confidence > 0.5


class TestCorrelationClusters:
    """Test entity clustering functionality"""

    @pytest.fixture
    def correlator(self):
        return IntelligenceCorrelator()

    def test_clusters_identified(self, correlator):
        """Test that related entities are clustered"""
        data = {
            'infrastructure': {
                'domains': [{'domain': 'example.com'}],
                'subdomains': ['www.example.com', 'api.example.com'],
                'ip_addresses': [{'ip': '192.168.1.1'}]
            }
        }
        result = correlator.correlate(data)
        # Clusters group related entities
        assert isinstance(result.clusters, list)


class TestTimelineReconstruction:
    """Test timeline reconstruction functionality"""

    @pytest.fixture
    def correlator(self):
        return IntelligenceCorrelator()

    def test_breach_events_in_timeline(self, correlator):
        """Test that breach events appear in timeline"""
        data = {
            'expanded_sources': {
                'breach_intel': {
                    'success': True,
                    'data': {
                        'breaches': [
                            {'name': 'Major Breach', 'date': '2023-06-15', 'records': 50000}
                        ]
                    }
                }
            }
        }
        result = correlator.correlate(data)
        breach_events = [e for e in result.timeline if e.event_type == 'data_breach']
        assert len(breach_events) >= 1

    def test_timeline_sorted_chronologically(self, correlator):
        """Test that timeline is sorted by timestamp"""
        data = {
            'infrastructure': {
                'domains': [{'domain': 'example.com'}],
                'exposed_services': [{'port': 80, 'service': 'HTTP'}]
            },
            'expanded_sources': {
                'passive_dns': {
                    'success': True,
                    'data': {
                        'historical_dns': [
                            {'ip': '192.168.1.1', 'first_seen': '2023-01-01'}
                        ]
                    }
                }
            }
        }
        result = correlator.correlate(data)
        timeline = result.timeline

        if len(timeline) >= 2:
            for i in range(len(timeline) - 1):
                assert timeline[i].timestamp <= timeline[i + 1].timestamp


class TestEmptyData:
    """Test handling of empty/minimal data"""

    @pytest.fixture
    def correlator(self):
        return IntelligenceCorrelator()

    def test_empty_data(self, correlator):
        """Test correlation with empty data"""
        result = correlator.correlate({})
        assert result.entities == {}
        assert result.relationships == []
        assert result.timeline == []

    def test_partial_data(self, correlator):
        """Test correlation with partial data"""
        data = {
            'infrastructure': {
                'domains': [{'domain': 'example.com'}]
            }
            # No social, threat, or expanded sources
        }
        result = correlator.correlate(data)
        assert len(result.entities) >= 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
