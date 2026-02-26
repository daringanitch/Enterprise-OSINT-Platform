"""
Unit tests for OSINT models and data structures
"""
import pytest
from datetime import datetime, timedelta
from models import (
    InvestigationType, InvestigationStatus, Priority, ComplianceFramework,
    TargetProfile, InvestigationScope, InvestigationProgress, IntelligenceResult,
    SocialIntelligence, InfrastructureIntelligence, ThreatIntelligence,
    IntelligenceResults, OSINTInvestigation, ComplianceAssessment, RiskScore
)


class TestEnums:
    """Test enum definitions"""
    
    def test_investigation_type_values(self):
        """Test InvestigationType enum values"""
        assert InvestigationType.COMPREHENSIVE.value == "comprehensive"
        assert InvestigationType.CORPORATE.value == "corporate"
        assert InvestigationType.INFRASTRUCTURE.value == "infrastructure"
        assert InvestigationType.SOCIAL_MEDIA.value == "social_media"
        assert InvestigationType.THREAT_ASSESSMENT.value == "threat_assessment"
        assert InvestigationType.COMPLIANCE_CHECK.value == "compliance_check"
    
    def test_investigation_status_values(self):
        """Test InvestigationStatus enum values"""
        assert InvestigationStatus.PENDING.value == "pending"
        assert InvestigationStatus.QUEUED.value == "queued"
        assert InvestigationStatus.PLANNING.value == "planning"
        assert InvestigationStatus.PROFILING.value == "profiling"
        assert InvestigationStatus.COLLECTING.value == "collecting"
        assert InvestigationStatus.ANALYZING.value == "analyzing"
        assert InvestigationStatus.ASSESSING_RISK.value == "assessing_risk"
        assert InvestigationStatus.VERIFYING.value == "verifying"
        assert InvestigationStatus.GENERATING_REPORT.value == "generating_report"
        assert InvestigationStatus.COMPLETED.value == "completed"
        assert InvestigationStatus.FAILED.value == "failed"
        assert InvestigationStatus.CANCELLED.value == "cancelled"
    
    def test_priority_values(self):
        """Test Priority enum values"""
        assert Priority.LOW.value == "low"
        assert Priority.NORMAL.value == "normal"
        assert Priority.HIGH.value == "high"
        assert Priority.URGENT.value == "urgent"
        assert Priority.CRITICAL.value == "critical"
    
    def test_compliance_framework_values(self):
        """Test ComplianceFramework enum values"""
        assert ComplianceFramework.GDPR.value == "gdpr"
        assert ComplianceFramework.CCPA.value == "ccpa"
        assert ComplianceFramework.PIPEDA.value == "pipeda"
        assert ComplianceFramework.LGPD.value == "lgpd"


class TestTargetProfile:
    """Test TargetProfile data class"""
    
    def test_target_profile_creation(self):
        """Test creating a target profile"""
        now = datetime.utcnow()
        profile = TargetProfile(
            target_id="target_123",
            target_type="domain",
            primary_identifier="example.com",
            created_at=now
        )
        
        assert profile.target_id == "target_123"
        assert profile.target_type == "domain"
        assert profile.primary_identifier == "example.com"
        assert profile.created_at == now
    
    def test_target_profile_with_optional_fields(self):
        """Test target profile with optional fields"""
        profile = TargetProfile(
            target_id="target_456",
            target_type="individual",
            primary_identifier="john.doe@example.com",
            created_at=datetime.utcnow(),
            secondary_identifiers=["@johndoe", "John Doe"],
            geographic_scope=["US", "CA"],
            data_retention_days=60
        )

        assert profile.secondary_identifiers == ["@johndoe", "John Doe"]
        assert profile.geographic_scope == ["US", "CA"]
        assert profile.data_retention_days == 60
    
    def test_target_profile_to_dict(self):
        """Test target profile conversion"""
        now = datetime.utcnow()
        profile = TargetProfile(
            target_id="target_789",
            target_type="ip_address",
            primary_identifier="192.168.1.1",
            created_at=now
        )

        # TargetProfile is a dataclass, can be converted via asdict
        from dataclasses import asdict
        profile_dict = asdict(profile)

        assert profile_dict["target_id"] == "target_789"
        assert profile_dict["target_type"] == "ip_address"
        assert profile_dict["primary_identifier"] == "192.168.1.1"


class TestInvestigationScope:
    """Test InvestigationScope data class"""
    
    def test_default_scope(self):
        """Test default investigation scope"""
        scope = InvestigationScope()

        assert scope.include_infrastructure is True
        assert scope.include_social_media is True
        assert scope.include_threat_intelligence is True
        assert scope.max_social_posts == 1000
        assert scope.max_investigation_hours == 24
        assert scope.exclude_pii is True
    
    def test_custom_scope(self):
        """Test custom investigation scope"""
        scope = InvestigationScope(
            include_social_media=False,
            max_social_posts=500,
            max_investigation_hours=12,
            exclude_pii=False
        )

        assert scope.include_social_media is False
        assert scope.max_social_posts == 500
        assert scope.max_investigation_hours == 12
        assert scope.exclude_pii is False
    
    def test_scope_to_dict(self):
        """Test scope dictionary conversion"""
        scope = InvestigationScope(
            include_infrastructure=True,
            max_threat_indicators=200
        )

        from dataclasses import asdict
        scope_dict = asdict(scope)

        assert scope_dict["include_infrastructure"] is True
        assert scope_dict["max_threat_indicators"] == 200


class TestInvestigationProgress:
    """Test InvestigationProgress data class"""
    
    def test_progress_initialization(self):
        """Test investigation progress initialization"""
        progress = InvestigationProgress()

        assert progress.overall_progress == 0.0
        assert progress.stage_progress == 0.0
        assert progress.current_activity == ""
        assert progress.data_points_collected == 0
        assert progress.warnings == []
        assert progress.estimated_completion is None
        assert isinstance(progress.last_updated, datetime)
    
    def test_progress_updates(self):
        """Test progress updates"""
        progress = InvestigationProgress()
        
        # Update progress
        progress.overall_progress = 0.5
        progress.stage_progress = 0.8
        progress.current_activity = "Collecting infrastructure data"
        progress.data_points_collected = 150
        progress.warnings.append("Rate limit encountered")
        progress.estimated_completion = datetime.utcnow() + timedelta(hours=2)
        
        assert progress.overall_progress == 0.5
        assert progress.stage_progress == 0.8
        assert progress.current_activity == "Collecting infrastructure data"
        assert progress.data_points_collected == 150
        assert "Rate limit encountered" in progress.warnings
        assert progress.estimated_completion is not None
    
    def test_progress_to_dict(self):
        """Test progress dictionary conversion"""
        now = datetime.utcnow()
        future = now + timedelta(hours=1)

        progress = InvestigationProgress(
            overall_progress=0.75,
            current_activity="Analyzing results",
            data_points_collected=500,
            warnings=["API quota low"],
            estimated_completion=future,
            last_updated=now
        )

        from dataclasses import asdict
        progress_dict = asdict(progress)

        assert progress_dict["overall_progress"] == 0.75
        assert progress_dict["current_activity"] == "Analyzing results"
        assert progress_dict["data_points_collected"] == 500
        assert progress_dict["warnings"] == ["API quota low"]


class TestIntelligenceResults:
    """Test intelligence result classes"""
    
    def test_intelligence_result_basic(self):
        """Test basic IntelligenceResult"""
        now = datetime.utcnow()
        result = IntelligenceResult(
            source="whois",
            data_type="domain_info",
            target="example.com",
            raw_data={"domain": "example.com", "registrar": "Test Registrar"},
            processed_data={"clean_data": "example.com"},
            confidence_score=0.9,
            timestamp=now,
            metadata={"source_url": "whois.com"}
        )

        assert result.source == "whois"
        assert result.data_type == "domain_info"
        assert result.target == "example.com"
        assert result.confidence_score == 0.9
        assert isinstance(result.timestamp, datetime)
    
    def test_social_intelligence(self):
        """Test SocialIntelligence data class"""
        social = SocialIntelligence(
            platforms={
                "twitter": {"username": "@example", "followers": 1000}
            },
            sentiment_analysis={"twitter": 0.1},
            engagement_metrics={"retweets": 50, "likes": 200},
            reputation_score=0.8,
            threat_indicators=["suspicious_account"],
            data_sources=[]
        )

        assert "twitter" in social.platforms
        assert social.platforms["twitter"]["followers"] == 1000
        assert social.reputation_score == 0.8
        assert "suspicious_account" in social.threat_indicators
    
    def test_infrastructure_intelligence(self):
        """Test InfrastructureIntelligence data class"""
        infra = InfrastructureIntelligence(
            domains=[{"domain": "example.com", "registrar": "Test"}],
            subdomains=["www.example.com", "api.example.com"],
            ip_addresses=[{"ip": "192.168.1.1", "provider": "Test"}],
            certificates=[{"subject": "example.com", "issuer": "Let's Encrypt"}],
            dns_records={"A": ["192.168.1.1"]},
            exposed_services=[],
            data_sources=[]
        )

        assert len(infra.domains) == 1
        assert len(infra.subdomains) == 2
        assert len(infra.ip_addresses) == 1
        assert len(infra.certificates) == 1
        assert "A" in infra.dns_records
    
    def test_threat_intelligence(self):
        """Test ThreatIntelligence data class"""
        threat = ThreatIntelligence(
            malware_indicators=[{"type": "domain", "value": "malicious.com", "confidence": 0.8}],
            network_indicators=[],
            behavioral_indicators=[],
            threat_actors=[],
            campaigns=[],
            risk_score=7.5,
            confidence_level=0.8,
            mitre_techniques=["T1566", "T1598"],
            data_sources=[]
        )

        assert len(threat.malware_indicators) == 1
        assert threat.risk_score == 7.5
        assert "T1566" in threat.mitre_techniques
    
    def test_intelligence_results_collection(self):
        """Test IntelligenceResults collection"""
        now = datetime.utcnow()
        social_result = IntelligenceResult(
            source="twitter",
            data_type="profile",
            target="example.com",
            raw_data={"username": "@example"},
            processed_data={},
            confidence_score=0.8,
            timestamp=now,
            metadata={}
        )

        infra_result = IntelligenceResult(
            source="whois",
            data_type="domain_info",
            target="example.com",
            raw_data={"domain": "example.com"},
            processed_data={},
            confidence_score=0.9,
            timestamp=now,
            metadata={}
        )

        results = IntelligenceResults(
            investigation_id="inv_123",
            target="example.com",
            results=[social_result, infra_result],
            total_sources=2,
            successful_sources=2,
            failed_sources=0
        )

        assert len(results.results) == 2
        assert results.total_sources == 2


class TestOSINTInvestigation:
    """Test OSINTInvestigation data class"""
    
    def test_investigation_creation(self):
        """Test creating an OSINT investigation"""
        target_profile = TargetProfile(
            target_id="target_123",
            target_type="domain",
            primary_identifier="example.com",
            created_at=datetime.utcnow()
        )

        investigation = OSINTInvestigation(
            id="inv_123",
            target_profile=target_profile,
            investigation_type=InvestigationType.COMPREHENSIVE,
            investigator_name="test_user",
            priority=Priority.HIGH,
            scope=InvestigationScope(),
            status=InvestigationStatus.PENDING,
            created_at=datetime.utcnow()
        )

        assert investigation.id == "inv_123"
        assert investigation.target_profile.primary_identifier == "example.com"
        assert investigation.investigation_type == InvestigationType.COMPREHENSIVE
        assert investigation.investigator_name == "test_user"
        assert investigation.priority == Priority.HIGH
        assert investigation.status == InvestigationStatus.PENDING
        assert isinstance(investigation.scope, InvestigationScope)
        assert isinstance(investigation.progress, InvestigationProgress)
    
    def test_investigation_timestamps(self):
        """Test investigation timestamp handling"""
        now = datetime.utcnow()
        later = now + timedelta(hours=1)
        
        target_profile = TargetProfile(
            target_id="target_456",
            target_type="domain", 
            primary_identifier="test.com",
            created_at=now
        )
        
        investigation = OSINTInvestigation(
            id="inv_456",
            target_profile=target_profile,
            investigation_type=InvestigationType.INFRASTRUCTURE,
            investigator_name="analyst",
            priority=Priority.NORMAL,
            scope=InvestigationScope(),
            status=InvestigationStatus.COMPLETED,
            created_at=now,
            started_at=now,
            completed_at=later
        )
        
        assert investigation.created_at == now
        assert investigation.started_at == now
        assert investigation.completed_at == later
    
    def test_investigation_to_dict(self):
        """Test investigation dictionary conversion"""
        now = datetime.utcnow()

        target_profile = TargetProfile(
            target_id="target_789",
            target_type="domain",
            primary_identifier="dict-test.com",
            created_at=now
        )

        investigation = OSINTInvestigation(
            id="inv_789",
            target_profile=target_profile,
            investigation_type=InvestigationType.SOCIAL_MEDIA,
            investigator_name="test_analyst",
            priority=Priority.LOW,
            scope=InvestigationScope(),
            status=InvestigationStatus.ANALYZING,
            created_at=now
        )

        inv_dict = investigation.to_dict()

        assert inv_dict["id"] == "inv_789"
        assert inv_dict["investigation_type"] == "social_media"
        assert inv_dict["investigator_name"] == "test_analyst"
        assert inv_dict["priority"] == "low"
        assert inv_dict["status"] == "analyzing"
        assert "target_profile" in inv_dict
        assert "scope" in inv_dict
        assert "progress" in inv_dict


class TestComplianceAndRisk:
    """Test compliance and risk assessment classes"""
    
    def test_compliance_assessment(self):
        """Test ComplianceAssessment data class"""
        from compliance_framework import ComplianceStatus, RiskLevel
        now = datetime.utcnow()
        assessment = ComplianceAssessment(
            assessment_id="assess_123",
            investigation_id="inv_123",
            framework=ComplianceFramework.GDPR,
            status=ComplianceStatus.COMPLIANT,
            risk_level=RiskLevel.LOW,
            compliance_score=95.0,
            data_categories_identified=[],
            processing_records=[],
            lawful_bases_applied=[],
            high_risk_factors=[],
            consent_requirements=[],
            retention_violations=[],
            cross_border_transfers=[],
            remediation_actions=[],
            policy_updates_required=[],
            training_requirements=[],
            assessed_by="test_user",
            assessed_at=now,
            next_review_date=now
        )

        assert assessment.framework == ComplianceFramework.GDPR
        assert assessment.compliance_score == 95.0
    
    def test_compliance_assessment_with_issues(self):
        """Test ComplianceAssessment with compliance issues"""
        from compliance_framework import ComplianceStatus, RiskLevel
        now = datetime.utcnow()
        assessment = ComplianceAssessment(
            assessment_id="assess_456",
            investigation_id="inv_456",
            framework=ComplianceFramework.CCPA,
            status=ComplianceStatus.NON_COMPLIANT,
            risk_level=RiskLevel.HIGH,
            compliance_score=35.0,
            data_categories_identified=[],
            processing_records=[],
            lawful_bases_applied=[],
            high_risk_factors=["Insufficient consent mechanism", "Data retention too long"],
            consent_requirements=["Implement consent banner"],
            retention_violations=["Reduce retention period"],
            cross_border_transfers=[],
            remediation_actions=["Implement consent banner", "Reduce retention period"],
            policy_updates_required=[],
            training_requirements=[],
            assessed_by="test_user",
            assessed_at=now,
            next_review_date=now
        )

        assert len(assessment.high_risk_factors) == 2
        assert "Insufficient consent mechanism" in assessment.high_risk_factors
        assert assessment.compliance_score == 35.0
    
    def test_risk_score(self):
        """Test RiskScore data class"""
        from advanced_analysis import RiskFactor, RiskCategory
        factor = RiskFactor(
            category=RiskCategory.REPUTATION,
            name="Domain age",
            score=6.0,
            weight=0.3,
            evidence=["Domain registered 2 years ago"]
        )
        risk = RiskScore(
            overall_score=7.5,
            risk_level="high",
            category_scores={"reputation": 6.0, "threat": 8.0},
            factors=[factor],
            trend="stable",
            confidence=0.85
        )

        assert risk.overall_score == 7.5
        assert risk.risk_level == "high"
        assert risk.category_scores["reputation"] == 6.0
        assert len(risk.factors) == 1
        assert risk.confidence == 0.85
    
    def test_risk_score_to_dict(self):
        """Test RiskScore dictionary conversion"""
        from advanced_analysis import RiskFactor, RiskCategory
        factor = RiskFactor(
            category=RiskCategory.REPUTATION,
            name="Recent activity",
            score=4.0,
            weight=0.3,
            evidence=["High activity detected"]
        )
        risk = RiskScore(
            overall_score=5.5,
            risk_level="medium",
            category_scores={"reputation": 4.0, "threat": 6.0},
            factors=[factor],
            trend="stable",
            confidence=0.9
        )

        risk_dict = risk.to_dict()

        assert risk_dict["overall_score"] == 5.5
        assert risk_dict["confidence"] == 0.9
        assert risk_dict["risk_level"] == "medium"


class TestDataValidation:
    """Test data validation and edge cases"""
    
    def test_empty_investigation_results(self):
        """Test handling empty investigation results"""
        results = IntelligenceResults(
            investigation_id="inv_empty",
            target="example.com"
        )

        assert len(results.results) == 0
        assert results.total_sources == 0
    
    def test_invalid_confidence_scores(self):
        """Test handling invalid confidence scores"""
        now = datetime.utcnow()
        result = IntelligenceResult(
            source="test",
            data_type="test_type",
            target="test_target",
            raw_data={"test": "data"},
            processed_data={},
            confidence_score=1.5,  # Invalid - should be 0-1, but model stores as-is
            timestamp=now,
            metadata={}
        )

        # The model should store the value as-is, validation would be at application level
        assert result.confidence_score == 1.5
    
    def test_missing_optional_fields(self):
        """Test handling missing optional fields"""
        # Create minimal investigation with only required fields
        target_profile = TargetProfile(
            target_id="minimal_target",
            target_type="domain",
            primary_identifier="minimal.com",
            created_at=datetime.utcnow()
        )

        investigation = OSINTInvestigation(
            id="minimal_inv",
            target_profile=target_profile,
            investigation_type=InvestigationType.COMPREHENSIVE,
            investigator_name="test",
            priority=Priority.NORMAL,
            scope=InvestigationScope(),
            status=InvestigationStatus.PENDING,
            created_at=datetime.utcnow()
        )

        # Optional fields should be None or default
        assert investigation.started_at is None
        assert investigation.completed_at is None
        assert investigation.processing_time_seconds == 0.0