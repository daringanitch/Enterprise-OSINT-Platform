#!/usr/bin/env python3
"""
Unit tests for advanced analysis module.

Tests:
- MITRE ATT&CK mapping
- Risk scoring engine
- Executive summary generation
- Trend analysis
- Chart data generation
"""

import pytest
import sys
import os
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from advanced_analysis import (
    MITRETactic, MITRETechnique, MITRE_TECHNIQUES, MITREMapper,
    RiskCategory, RiskFactor, RiskScore, RiskScoringEngine,
    ExecutiveSummaryGenerator, TrendAnalyzer, ChartDataGenerator,
    AdvancedAnalysisEngine, advanced_analysis_engine
)


class TestMITRETactic:
    """Test MITRETactic enum"""

    def test_enum_values(self):
        """Test enum values exist"""
        assert MITRETactic.RECONNAISSANCE.value == 'reconnaissance'
        assert MITRETactic.INITIAL_ACCESS.value == 'initial_access'
        assert MITRETactic.CREDENTIAL_ACCESS.value == 'credential_access'
        assert MITRETactic.EXFILTRATION.value == 'exfiltration'


class TestMITRETechnique:
    """Test MITRETechnique dataclass"""

    def test_create_technique(self):
        """Test creating a technique"""
        technique = MITRETechnique(
            technique_id='T1234',
            name='Test Technique',
            tactic=MITRETactic.RECONNAISSANCE,
            description='Test description'
        )
        assert technique.technique_id == 'T1234'
        assert technique.severity == 'medium'  # Default

    def test_techniques_exist(self):
        """Test that MITRE_TECHNIQUES dict is populated"""
        assert len(MITRE_TECHNIQUES) > 0
        assert 'T1190' in MITRE_TECHNIQUES
        assert 'T1566' in MITRE_TECHNIQUES


class TestMITREMapper:
    """Test MITREMapper class"""

    @pytest.fixture
    def sample_findings(self):
        """Sample findings for testing"""
        return {
            'infrastructure': {
                'exposed_services': [
                    {'port': 80, 'service': 'HTTP'},
                    {'port': 22, 'service': 'SSH'}
                ],
                'subdomains': ['www.example.com', 'api.example.com']
            },
            'threat': {
                'malware_indicators': [
                    {'type': 'md5', 'value': 'abc123'}
                ],
                'network_indicators': [
                    {'ip': '192.168.1.1', 'threat_type': 'c2'}
                ],
                'threat_actors': [
                    {'name': 'APT-TEST'}
                ]
            },
            'expanded_sources': {
                'breach_intel': {
                    'success': True,
                    'data': {
                        'breaches': [{'name': 'Test Breach', 'date': '2023-01-01'}]
                    }
                },
                'url_intel': {
                    'success': True,
                    'data': {
                        'malicious_urls': [{'url': 'http://bad.com', 'threat_type': 'phishing'}]
                    }
                }
            }
        }

    def test_map_findings_returns_list(self, sample_findings):
        """Test that map_findings returns a list"""
        result = MITREMapper.map_findings(sample_findings)
        assert isinstance(result, list)

    def test_map_findings_extracts_techniques(self, sample_findings):
        """Test that techniques are extracted from findings"""
        result = MITREMapper.map_findings(sample_findings)
        assert len(result) > 0

    def test_technique_has_required_fields(self, sample_findings):
        """Test that mapped techniques have required fields"""
        result = MITREMapper.map_findings(sample_findings)
        if result:
            technique = result[0]
            assert 'technique_id' in technique
            assert 'name' in technique
            assert 'tactic' in technique
            assert 'severity' in technique
            assert 'evidence' in technique

    def test_attack_surface_summary(self, sample_findings):
        """Test attack surface summary generation"""
        techniques = MITREMapper.map_findings(sample_findings)
        summary = MITREMapper.get_attack_surface_summary(techniques)

        assert 'total_techniques' in summary
        assert 'tactics_covered' in summary
        assert 'attack_surface_score' in summary
        assert summary['total_techniques'] == len(techniques)

    def test_empty_findings(self):
        """Test mapping with empty findings"""
        result = MITREMapper.map_findings({})
        assert isinstance(result, list)
        assert len(result) == 0


class TestRiskCategory:
    """Test RiskCategory enum"""

    def test_enum_values(self):
        """Test enum values exist"""
        assert RiskCategory.INFRASTRUCTURE.value == 'infrastructure'
        assert RiskCategory.THREAT.value == 'threat'
        assert RiskCategory.CREDENTIAL.value == 'credential'
        assert RiskCategory.COMPLIANCE.value == 'compliance'


class TestRiskFactor:
    """Test RiskFactor dataclass"""

    def test_create_risk_factor(self):
        """Test creating a risk factor"""
        factor = RiskFactor(
            category=RiskCategory.THREAT,
            name='Test Factor',
            score=75.0,
            weight=0.5,
            evidence=['Evidence 1']
        )
        assert factor.score == 75.0
        assert factor.category == RiskCategory.THREAT


class TestRiskScore:
    """Test RiskScore dataclass"""

    def test_create_risk_score(self):
        """Test creating a risk score"""
        score = RiskScore(
            overall_score=65.0,
            risk_level='high',
            category_scores={'threat': 70.0},
            factors=[],
            trend='stable',
            confidence=0.8
        )
        assert score.overall_score == 65.0
        assert score.risk_level == 'high'

    def test_to_dict(self):
        """Test serialization to dict"""
        score = RiskScore(
            overall_score=50.0,
            risk_level='medium',
            category_scores={'threat': 60.0, 'infrastructure': 40.0},
            factors=[],
            trend='increasing',
            confidence=0.75
        )
        d = score.to_dict()
        assert d['overall_score'] == 50.0
        assert d['risk_level'] == 'medium'
        assert 'category_scores' in d


class TestRiskScoringEngine:
    """Test RiskScoringEngine class"""

    @pytest.fixture
    def engine(self):
        return RiskScoringEngine()

    @pytest.fixture
    def sample_findings(self):
        return {
            'infrastructure': {
                'exposed_services': [
                    {'port': 22, 'service': 'SSH'},
                    {'port': 3389, 'service': 'RDP'}
                ],
                'subdomains': ['a.com', 'b.com', 'c.com'] * 5
            },
            'threat': {
                'malware_indicators': [{'type': 'hash', 'value': 'abc'}],
                'network_indicators': [{'threat_type': 'c2'}]
            },
            'expanded_sources': {
                'breach_intel': {
                    'success': True,
                    'data': {
                        'breaches': [{'name': 'Breach1'}],
                        'total_records_exposed': 10000
                    }
                }
            }
        }

    def test_calculate_risk_returns_score(self, engine, sample_findings):
        """Test that calculate_risk returns a RiskScore"""
        result = engine.calculate_risk(sample_findings)
        assert isinstance(result, RiskScore)

    def test_risk_score_range(self, engine, sample_findings):
        """Test that risk score is in valid range"""
        result = engine.calculate_risk(sample_findings)
        assert 0 <= result.overall_score <= 100

    def test_risk_level_assigned(self, engine, sample_findings):
        """Test that risk level is assigned"""
        result = engine.calculate_risk(sample_findings)
        assert result.risk_level in ['critical', 'high', 'medium', 'low']

    def test_category_scores_calculated(self, engine, sample_findings):
        """Test that category scores are calculated"""
        result = engine.calculate_risk(sample_findings)
        assert len(result.category_scores) > 0

    def test_factors_generated(self, engine, sample_findings):
        """Test that risk factors are generated"""
        result = engine.calculate_risk(sample_findings)
        assert len(result.factors) > 0

    def test_high_risk_services_increase_score(self, engine):
        """Test that high-risk ports increase risk score"""
        low_risk = {'infrastructure': {'exposed_services': [{'port': 80, 'service': 'HTTP'}]}}
        high_risk = {'infrastructure': {'exposed_services': [{'port': 22, 'service': 'SSH'}]}}

        low_result = engine.calculate_risk(low_risk)
        high_result = engine.calculate_risk(high_risk)

        # High-risk ports should increase score
        assert high_result.overall_score >= low_result.overall_score

    def test_mitre_mapping_affects_score(self, engine, sample_findings):
        """Test that MITRE mapping affects risk score"""
        mitre_mapping = [
            {'severity': 'critical', 'technique_id': 'T1190'},
            {'severity': 'high', 'technique_id': 'T1566'}
        ]
        result = engine.calculate_risk(sample_findings, None, mitre_mapping)

        # Should have higher score due to critical techniques
        assert result.overall_score > 0

    def test_empty_findings(self, engine):
        """Test risk calculation with empty findings"""
        result = engine.calculate_risk({})
        assert isinstance(result, RiskScore)
        assert result.overall_score == 0


class TestExecutiveSummaryGenerator:
    """Test ExecutiveSummaryGenerator class"""

    @pytest.fixture
    def generator(self):
        return ExecutiveSummaryGenerator()

    @pytest.fixture
    def sample_risk_score(self):
        return RiskScore(
            overall_score=65.0,
            risk_level='high',
            category_scores={'threat': 70.0, 'infrastructure': 60.0},
            factors=[
                RiskFactor(
                    category=RiskCategory.THREAT,
                    name='Malware Detected',
                    score=80.0,
                    weight=0.5,
                    evidence=['Malware found'],
                    recommendations=['Remove malware']
                )
            ],
            trend='stable',
            confidence=0.8
        )

    @pytest.fixture
    def sample_mitre(self):
        return [
            {
                'technique_id': 'T1190',
                'name': 'Exploit App',
                'tactic': 'initial_access',
                'severity': 'critical',
                'description': 'Test',
                'mitigation': 'Patch systems'
            }
        ]

    def test_generate_summary_returns_dict(self, generator, sample_risk_score, sample_mitre):
        """Test that generate_summary returns a dict"""
        result = generator.generate_summary(
            'example.com',
            sample_risk_score,
            sample_mitre,
            {}
        )
        assert isinstance(result, dict)

    def test_summary_has_required_sections(self, generator, sample_risk_score, sample_mitre):
        """Test that summary has required sections"""
        result = generator.generate_summary(
            'example.com',
            sample_risk_score,
            sample_mitre,
            {}
        )
        assert 'title' in result
        assert 'overview' in result
        assert 'key_findings' in result
        assert 'recommendations' in result
        assert 'conclusion' in result

    def test_overview_mentions_target(self, generator, sample_risk_score, sample_mitre):
        """Test that overview mentions the target"""
        result = generator.generate_summary(
            'test-target.com',
            sample_risk_score,
            sample_mitre,
            {}
        )
        assert 'test-target.com' in result['overview']

    def test_recommendations_generated(self, generator, sample_risk_score, sample_mitre):
        """Test that recommendations are generated"""
        result = generator.generate_summary(
            'example.com',
            sample_risk_score,
            sample_mitre,
            {}
        )
        assert len(result['recommendations']) > 0


class TestTrendAnalyzer:
    """Test TrendAnalyzer class"""

    @pytest.fixture
    def analyzer(self):
        return TrendAnalyzer()

    @pytest.fixture
    def sample_timeline(self):
        return [
            {'timestamp': '2024-01-15T10:00:00', 'event_type': 'discovery', 'severity': 'info'},
            {'timestamp': '2024-01-16T11:00:00', 'event_type': 'alert', 'severity': 'warning'},
            {'timestamp': '2024-02-01T12:00:00', 'event_type': 'breach', 'severity': 'critical'},
            {'timestamp': '2024-02-15T13:00:00', 'event_type': 'discovery', 'severity': 'info'},
        ]

    def test_analyze_trends_returns_dict(self, analyzer, sample_timeline):
        """Test that analyze_trends returns a dict"""
        result = analyzer.analyze_trends(sample_timeline)
        assert isinstance(result, dict)

    def test_trend_available_with_data(self, analyzer, sample_timeline):
        """Test that trend_available is True with data"""
        result = analyzer.analyze_trends(sample_timeline)
        assert result['trend_available'] is True

    def test_empty_timeline(self, analyzer):
        """Test analysis with empty timeline"""
        result = analyzer.analyze_trends([])
        assert result['trend_available'] is False

    def test_event_distribution_calculated(self, analyzer, sample_timeline):
        """Test that event distribution is calculated"""
        result = analyzer.analyze_trends(sample_timeline)
        assert 'event_distribution' in result
        assert len(result['event_distribution']) > 0

    def test_severity_distribution_calculated(self, analyzer, sample_timeline):
        """Test that severity distribution is calculated"""
        result = analyzer.analyze_trends(sample_timeline)
        assert 'severity_distribution' in result


class TestChartDataGenerator:
    """Test ChartDataGenerator class"""

    @pytest.fixture
    def sample_risk_score(self):
        return RiskScore(
            overall_score=65.0,
            risk_level='high',
            category_scores={
                'threat': 70.0,
                'infrastructure': 60.0,
                'credential': 50.0
            },
            factors=[],
            trend='stable',
            confidence=0.8
        )

    def test_risk_distribution_chart(self, sample_risk_score):
        """Test risk distribution chart generation"""
        result = ChartDataGenerator.risk_distribution_chart(sample_risk_score)
        assert result['chart_type'] == 'pie'
        assert 'data' in result
        assert len(result['data']) > 0

    def test_severity_bar_chart(self):
        """Test severity bar chart generation"""
        mitre_mapping = [
            {'severity': 'critical'},
            {'severity': 'high'},
            {'severity': 'high'},
            {'severity': 'medium'}
        ]
        result = ChartDataGenerator.severity_bar_chart(mitre_mapping)
        assert result['chart_type'] == 'bar'
        assert 'data' in result

    def test_timeline_chart(self):
        """Test timeline chart generation"""
        timeline = [
            {'timestamp': '2024-01-15T10:00:00', 'severity': 'info'},
            {'timestamp': '2024-01-15T11:00:00', 'severity': 'critical'},
            {'timestamp': '2024-02-01T12:00:00', 'severity': 'warning'}
        ]
        result = ChartDataGenerator.timeline_chart(timeline)
        assert result['chart_type'] == 'stacked_bar'
        assert 'categories' in result
        assert 'series' in result

    def test_entity_type_chart(self):
        """Test entity type chart generation"""
        entities = {
            'ent1': {'type': 'domain'},
            'ent2': {'type': 'domain'},
            'ent3': {'type': 'ip_address'},
            'ent4': {'type': 'email'}
        }
        result = ChartDataGenerator.entity_type_chart(entities)
        assert result['chart_type'] == 'horizontal_bar'
        assert 'data' in result

    def test_risk_gauge_chart(self, sample_risk_score):
        """Test risk gauge chart generation"""
        result = ChartDataGenerator.risk_gauge_chart(sample_risk_score)
        assert result['chart_type'] == 'gauge'
        assert result['value'] == 65.0
        assert 'thresholds' in result


class TestAdvancedAnalysisEngine:
    """Test AdvancedAnalysisEngine class"""

    @pytest.fixture
    def engine(self):
        return AdvancedAnalysisEngine()

    @pytest.fixture
    def sample_findings(self):
        return {
            'infrastructure': {
                'exposed_services': [{'port': 80, 'service': 'HTTP'}],
                'subdomains': ['www.example.com']
            },
            'threat': {
                'malware_indicators': [{'type': 'hash', 'value': 'abc'}]
            }
        }

    @pytest.fixture
    def sample_correlation(self):
        return {
            'entities': {
                'ent1': {'type': 'domain', 'value': 'example.com'}
            },
            'timeline': [
                {'timestamp': '2024-01-15T10:00:00', 'event_type': 'discovery', 'severity': 'info'}
            ]
        }

    def test_analyze_returns_dict(self, engine, sample_findings):
        """Test that analyze returns a dict"""
        result = engine.analyze('example.com', sample_findings)
        assert isinstance(result, dict)

    def test_analyze_includes_risk_score(self, engine, sample_findings):
        """Test that analysis includes risk score"""
        result = engine.analyze('example.com', sample_findings)
        assert 'risk_score' in result

    def test_analyze_includes_mitre_mapping(self, engine, sample_findings):
        """Test that analysis includes MITRE mapping"""
        result = engine.analyze('example.com', sample_findings)
        assert 'mitre_mapping' in result

    def test_analyze_includes_executive_summary(self, engine, sample_findings):
        """Test that analysis includes executive summary"""
        result = engine.analyze('example.com', sample_findings)
        assert 'executive_summary' in result

    def test_analyze_includes_charts(self, engine, sample_findings):
        """Test that analysis includes chart data"""
        result = engine.analyze('example.com', sample_findings)
        assert 'charts' in result

    def test_analyze_with_correlation(self, engine, sample_findings, sample_correlation):
        """Test analysis with correlation results"""
        result = engine.analyze('example.com', sample_findings, sample_correlation)
        assert 'trends' in result


class TestGlobalEngine:
    """Test global engine instance"""

    def test_global_instance_exists(self):
        """Test that global instance is available"""
        assert advanced_analysis_engine is not None

    def test_global_instance_is_engine(self):
        """Test that global instance is AdvancedAnalysisEngine"""
        assert isinstance(advanced_analysis_engine, AdvancedAnalysisEngine)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
