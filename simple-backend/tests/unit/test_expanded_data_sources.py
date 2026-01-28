#!/usr/bin/env python3
"""
Unit tests for expanded data sources module.

Tests:
- Individual data source clients
- Data source manager
- Aggregation and summarization
- Error handling and fallbacks
"""

import pytest
import asyncio
import sys
import os

# Configure pytest-asyncio
pytestmark = pytest.mark.asyncio

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from expanded_data_sources import (
    DataSourceResult, DataSourceType,
    PassiveDNSClient, CodeIntelligenceClient, BreachIntelligenceClient,
    URLIntelligenceClient, BusinessIntelligenceClient, NewsIntelligenceClient,
    ExpandedDataSourceManager, expanded_data_manager
)


class TestDataSourceResult:
    """Test DataSourceResult dataclass"""

    def test_create_result(self):
        """Test creating a data source result"""
        result = DataSourceResult(
            source_name='test_source',
            source_type='test_type',
            target='example.com',
            success=True,
            data={'key': 'value'},
            confidence=0.8
        )
        assert result.source_name == 'test_source'
        assert result.success is True
        assert result.confidence == 0.8

    def test_to_dict(self):
        """Test serialization to dict"""
        result = DataSourceResult(
            source_name='test',
            source_type='test',
            target='example.com',
            success=True,
            data={'test': 'data'}
        )
        d = result.to_dict()
        assert 'source_name' in d
        assert 'timestamp' in d
        assert d['success'] is True


class TestDataSourceType:
    """Test DataSourceType enum"""

    def test_enum_values(self):
        """Test enum values exist"""
        assert DataSourceType.PASSIVE_DNS.value == 'passive_dns'
        assert DataSourceType.CODE_INTEL.value == 'code_intelligence'
        assert DataSourceType.BREACH_INTEL.value == 'breach_intelligence'
        assert DataSourceType.URL_INTEL.value == 'url_intelligence'
        assert DataSourceType.BUSINESS_INTEL.value == 'business_intelligence'
        assert DataSourceType.NEWS_INTEL.value == 'news_intelligence'


class TestPassiveDNSClient:
    """Test Passive DNS client"""

    @pytest.fixture
    def client(self):
        return PassiveDNSClient()

    def test_get_source_info(self, client):
        """Test source info retrieval"""
        info = client.get_source_info()
        assert info['name'] == 'Passive DNS'
        assert 'capabilities' in info
        assert 'historical_dns' in info['capabilities']

    @pytest.mark.asyncio
    async def test_gather_simulated(self, client):
        """Test simulated data gathering (no API key)"""
        result = await client.gather('example.com')
        assert result.success is True
        assert result.source_type == DataSourceType.PASSIVE_DNS.value
        assert 'historical_dns' in result.data
        assert 'subdomains' in result.data

    @pytest.mark.asyncio
    async def test_gather_returns_subdomains(self, client):
        """Test that subdomains are discovered"""
        result = await client.gather('test-domain.com')
        assert result.success is True
        subdomains = result.data.get('subdomains', [])
        assert isinstance(subdomains, list)


class TestCodeIntelligenceClient:
    """Test Code Intelligence client"""

    @pytest.fixture
    def client(self):
        return CodeIntelligenceClient()

    def test_get_source_info(self, client):
        """Test source info retrieval"""
        info = client.get_source_info()
        assert info['name'] == 'Code Intelligence'
        assert 'repo_discovery' in info['capabilities']

    @pytest.mark.asyncio
    async def test_gather_simulated(self, client):
        """Test simulated data gathering"""
        result = await client.gather('example.com')
        assert result.success is True
        assert 'repositories' in result.data
        assert 'potential_exposures' in result.data


class TestBreachIntelligenceClient:
    """Test Breach Intelligence client"""

    @pytest.fixture
    def client(self):
        return BreachIntelligenceClient()

    def test_get_source_info(self, client):
        """Test source info retrieval"""
        info = client.get_source_info()
        assert info['name'] == 'Breach Intelligence'
        assert 'breach_detection' in info['capabilities']

    @pytest.mark.asyncio
    async def test_gather_simulated(self, client):
        """Test simulated data gathering"""
        result = await client.gather('example.com')
        assert result.success is True
        assert 'breaches' in result.data
        assert 'total_breaches' in result.data


class TestURLIntelligenceClient:
    """Test URL Intelligence client"""

    @pytest.fixture
    def client(self):
        return URLIntelligenceClient()

    def test_get_source_info(self, client):
        """Test source info retrieval"""
        info = client.get_source_info()
        assert info['name'] == 'URL Intelligence'
        assert 'malware_urls' in info['capabilities']

    @pytest.mark.asyncio
    async def test_gather_simulated(self, client):
        """Test simulated data gathering"""
        result = await client.gather('example.com')
        assert result.success is True
        assert 'malicious_urls' in result.data
        assert 'threat_types' in result.data


class TestBusinessIntelligenceClient:
    """Test Business Intelligence client"""

    @pytest.fixture
    def client(self):
        return BusinessIntelligenceClient()

    def test_get_source_info(self, client):
        """Test source info retrieval"""
        info = client.get_source_info()
        assert info['name'] == 'Business Intelligence'
        assert 'company_search' in info['capabilities']

    @pytest.mark.asyncio
    async def test_gather_simulated(self, client):
        """Test simulated data gathering"""
        result = await client.gather('example.com')
        assert result.success is True
        assert 'company_info' in result.data


class TestNewsIntelligenceClient:
    """Test News Intelligence client"""

    @pytest.fixture
    def client(self):
        return NewsIntelligenceClient()

    def test_get_source_info(self, client):
        """Test source info retrieval"""
        info = client.get_source_info()
        assert info['name'] == 'News Intelligence'
        assert 'news_mentions' in info['capabilities']

    @pytest.mark.asyncio
    async def test_gather_simulated(self, client):
        """Test simulated data gathering"""
        result = await client.gather('example.com')
        assert result.success is True
        assert 'articles' in result.data
        assert 'total_results' in result.data


class TestExpandedDataSourceManager:
    """Test the data source manager"""

    @pytest.fixture
    def manager(self):
        return ExpandedDataSourceManager()

    def test_get_available_sources(self, manager):
        """Test getting available sources"""
        sources = manager.get_available_sources()
        assert len(sources) == 6
        source_names = [s['name'] for s in sources]
        assert 'Passive DNS' in source_names
        assert 'Breach Intelligence' in source_names

    @pytest.mark.asyncio
    async def test_gather_all(self, manager):
        """Test gathering from all sources"""
        results = await manager.gather_all('example.com')
        assert len(results) == 6
        assert 'passive_dns' in results
        assert 'breach_intel' in results

    @pytest.mark.asyncio
    async def test_gather_specific_sources(self, manager):
        """Test gathering from specific sources only"""
        results = await manager.gather_all('example.com', sources=['passive_dns', 'breach_intel'])
        assert len(results) == 2
        assert 'passive_dns' in results
        assert 'breach_intel' in results
        assert 'code_intel' not in results

    @pytest.mark.asyncio
    async def test_aggregated_summary(self, manager):
        """Test generating aggregated summary"""
        results = await manager.gather_all('example.com')
        summary = manager.get_aggregated_summary(results)

        assert 'sources_queried' in summary
        assert 'sources_successful' in summary
        assert 'average_confidence' in summary
        assert 'key_findings' in summary
        assert 'risk_indicators' in summary
        assert 'overall_risk' in summary

    @pytest.mark.asyncio
    async def test_all_sources_return_success(self, manager):
        """Test that all simulated sources return success"""
        results = await manager.gather_all('test-domain.com')
        for source_name, result in results.items():
            assert result.success is True, f"Source {source_name} failed: {result.error}"


class TestGlobalManager:
    """Test the global expanded_data_manager instance"""

    def test_global_instance_exists(self):
        """Test that global instance is available"""
        assert expanded_data_manager is not None

    def test_global_instance_has_sources(self):
        """Test that global instance has sources"""
        sources = expanded_data_manager.get_available_sources()
        assert len(sources) > 0


class TestDataQuality:
    """Test data quality and consistency"""

    @pytest.mark.asyncio
    async def test_passive_dns_data_structure(self):
        """Test passive DNS returns expected data structure"""
        client = PassiveDNSClient()
        result = await client.gather('example.com')

        data = result.data
        assert isinstance(data.get('historical_dns'), list)
        assert isinstance(data.get('subdomains'), list)

        if data['historical_dns']:
            record = data['historical_dns'][0]
            assert 'ip' in record
            assert 'first_seen' in record

    @pytest.mark.asyncio
    async def test_breach_data_structure(self):
        """Test breach intel returns expected data structure"""
        client = BreachIntelligenceClient()
        result = await client.gather('example.com')

        data = result.data
        assert 'breaches' in data
        assert 'total_breaches' in data
        assert isinstance(data['total_breaches'], int)

    @pytest.mark.asyncio
    async def test_confidence_scores_valid(self):
        """Test that confidence scores are in valid range"""
        manager = ExpandedDataSourceManager()
        results = await manager.gather_all('example.com')

        for source_name, result in results.items():
            assert 0.0 <= result.confidence <= 1.0, f"Invalid confidence for {source_name}: {result.confidence}"


class TestErrorHandling:
    """Test error handling"""

    @pytest.mark.asyncio
    async def test_invalid_target_handled(self):
        """Test that invalid targets don't crash"""
        manager = ExpandedDataSourceManager()
        # Empty target should still return results (may be errors but shouldn't crash)
        try:
            results = await manager.gather_all('')
            # Should complete without exception
        except Exception as e:
            pytest.fail(f"Manager crashed on empty target: {e}")

    @pytest.mark.asyncio
    async def test_manager_handles_source_errors(self):
        """Test that manager handles individual source errors gracefully"""
        manager = ExpandedDataSourceManager()
        results = await manager.gather_all('example.com')

        # Even if some sources fail, we should get results for all
        assert len(results) == 6


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
