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
            target_type="person",
            primary_identifier="john.doe@example.com",
            created_at=datetime.utcnow(),
            secondary_identifiers=["@johndoe", "John Doe"],
            description="Test target",
            tags=["social_media", "corporate"]
        )
        
        assert profile.secondary_identifiers == ["@johndoe", "John Doe"]
        assert profile.description == "Test target"
        assert profile.tags == ["social_media", "corporate"]
    
    def test_target_profile_to_dict(self):
        """Test target profile dictionary conversion"""
        now = datetime.utcnow()
        profile = TargetProfile(
            target_id="target_789",
            target_type="ip",
            primary_identifier="192.168.1.1",
            created_at=now
        )
        
        profile_dict = profile.to_dict()
        
        assert profile_dict["target_id"] == "target_789"
        assert profile_dict["target_type"] == "ip"
        assert profile_dict["primary_identifier"] == "192.168.1.1"
        assert profile_dict["created_at"] == now.isoformat()


class TestInvestigationScope:
    """Test InvestigationScope data class"""
    
    def test_default_scope(self):
        """Test default investigation scope"""
        scope = InvestigationScope()
        
        assert scope.include_infrastructure is True
        assert scope.include_social_media is True
        assert scope.include_threat_intelligence is True
        assert scope.include_dark_web is False
        assert scope.max_data_points == 10000
        assert scope.max_investigation_time_hours == 24
        assert scope.compliance_frameworks == []
    
    def test_custom_scope(self):
        """Test custom investigation scope"""
        scope = InvestigationScope(
            include_social_media=False,
            include_dark_web=True,
            max_data_points=5000,
            max_investigation_time_hours=12,
            compliance_frameworks=[ComplianceFramework.GDPR, ComplianceFramework.CCPA]
        )
        
        assert scope.include_social_media is False
        assert scope.include_dark_web is True
        assert scope.max_data_points == 5000
        assert scope.max_investigation_time_hours == 12
        assert ComplianceFramework.GDPR in scope.compliance_frameworks
        assert ComplianceFramework.CCPA in scope.compliance_frameworks
    
    def test_scope_to_dict(self):
        """Test scope dictionary conversion"""
        scope = InvestigationScope(
            include_infrastructure=True,
            max_data_points=2000,
            compliance_frameworks=[ComplianceFramework.PIPEDA]
        )
        
        scope_dict = scope.to_dict()
        
        assert scope_dict["include_infrastructure"] is True
        assert scope_dict["max_data_points"] == 2000
        assert scope_dict["compliance_frameworks"] == ["pipeda"]


class TestInvestigationProgress:
    """Test InvestigationProgress data class"""
    
    def test_progress_initialization(self):
        """Test investigation progress initialization"""
        progress = InvestigationProgress()
        
        assert progress.overall_progress == 0.0
        assert progress.stage_progress == 0.0
        assert progress.current_activity == "Initializing investigation"
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
        
        progress_dict = progress.to_dict()
        
        assert progress_dict["overall_progress"] == 0.75
        assert progress_dict["current_activity"] == "Analyzing results"
        assert progress_dict["data_points_collected"] == 500
        assert progress_dict["warnings"] == ["API quota low"]
        assert progress_dict["estimated_completion"] == future.isoformat()
        assert progress_dict["last_updated"] == now.isoformat()


class TestIntelligenceResults:
    """Test intelligence result classes"""
    
    def test_intelligence_result_basic(self):
        """Test basic IntelligenceResult"""
        result = IntelligenceResult(
            source="whois",
            data={"domain": "example.com", "registrar": "Test Registrar"},
            confidence=0.9,
            timestamp=datetime.utcnow()
        )
        
        assert result.source == "whois"
        assert result.data["domain"] == "example.com"
        assert result.confidence == 0.9
        assert isinstance(result.timestamp, datetime)
    
    def test_social_intelligence(self):
        """Test SocialIntelligence data class"""
        social = SocialIntelligence(
            platform="twitter",
            profiles=[{"username": "@example", "followers": 1000}],
            posts=[{"content": "Test post", "engagement": 50}],
            mentions=[{"text": "Mentioned in news", "source": "news.com"}],
            sentiment_analysis={"overall": "neutral", "score": 0.1}
        )
        
        assert social.platform == "twitter"
        assert len(social.profiles) == 1
        assert len(social.posts) == 1
        assert len(social.mentions) == 1
        assert social.sentiment_analysis["overall"] == "neutral"
    
    def test_infrastructure_intelligence(self):
        """Test InfrastructureIntelligence data class"""
        infra = InfrastructureIntelligence(
            domains=[{"domain": "example.com", "registrar": "Test"}],
            subdomains=["www.example.com", "api.example.com"],
            ip_addresses=["192.168.1.1"],
            certificates=[{"subject": "example.com", "issuer": "Let's Encrypt"}],
            dns_records=[{"type": "A", "value": "192.168.1.1"}],
            hosting_info={"provider": "AWS", "location": "us-east-1"}
        )
        
        assert len(infra.domains) == 1
        assert len(infra.subdomains) == 2
        assert len(infra.ip_addresses) == 1
        assert len(infra.certificates) == 1
        assert len(infra.dns_records) == 1
        assert infra.hosting_info["provider"] == "AWS"
    
    def test_threat_intelligence(self):
        """Test ThreatIntelligence data class"""
        threat = ThreatIntelligence(
            indicators=[{"type": "domain", "value": "malicious.com", "confidence": 0.8}],
            malware_families=["trojan", "ransomware"],
            attack_vectors=["phishing", "social_engineering"],
            risk_scores={"overall": 7.5, "malware": 8.0, "reputation": 6.0},
            blocklist_status={"virustotal": "clean", "malware_bazaar": "suspicious"}
        )
        
        assert len(threat.indicators) == 1
        assert "trojan" in threat.malware_families
        assert "phishing" in threat.attack_vectors
        assert threat.risk_scores["overall"] == 7.5
        assert threat.blocklist_status["virustotal"] == "clean"
    
    def test_intelligence_results_collection(self):
        """Test IntelligenceResults collection"""
        social_result = IntelligenceResult(
            source="twitter",
            data={"username": "@example"},
            confidence=0.8,
            timestamp=datetime.utcnow()
        )
        
        infra_result = IntelligenceResult(
            source="whois",
            data={"domain": "example.com"},
            confidence=0.9,
            timestamp=datetime.utcnow()
        )
        
        results = IntelligenceResults(
            social_intelligence=[social_result],
            infrastructure_intelligence=[infra_result],
            threat_intelligence=[]
        )
        
        assert len(results.social_intelligence) == 1
        assert len(results.infrastructure_intelligence) == 1
        assert len(results.threat_intelligence) == 0
        
        # Test getting all results
        all_results = results.get_all_results()
        assert len(all_results) == 2


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
        assert isinstance(investigation.intelligence_results, IntelligenceResults)
    
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
        assert inv_dict["created_at"] == now.isoformat()
        assert "target_profile" in inv_dict
        assert "scope" in inv_dict
        assert "progress" in inv_dict
        assert "intelligence_results" in inv_dict


class TestComplianceAndRisk:
    """Test compliance and risk assessment classes"""
    
    def test_compliance_assessment(self):
        """Test ComplianceAssessment data class"""
        assessment = ComplianceAssessment(
            framework=ComplianceFramework.GDPR,
            compliant=True,
            issues=[],
            recommendations=["Continue current practices"],
            risk_level="low",
            assessed_at=datetime.utcnow()
        )
        
        assert assessment.framework == ComplianceFramework.GDPR
        assert assessment.compliant is True
        assert len(assessment.issues) == 0
        assert len(assessment.recommendations) == 1
        assert assessment.risk_level == "low"
        assert isinstance(assessment.assessed_at, datetime)
    
    def test_compliance_assessment_with_issues(self):
        """Test ComplianceAssessment with compliance issues"""
        assessment = ComplianceAssessment(
            framework=ComplianceFramework.CCPA,
            compliant=False,
            issues=["Insufficient consent mechanism", "Data retention too long"],
            recommendations=["Implement consent banner", "Reduce retention period"],
            risk_level="high",
            assessed_at=datetime.utcnow()
        )
        
        assert assessment.compliant is False
        assert len(assessment.issues) == 2
        assert "Insufficient consent mechanism" in assessment.issues
        assert assessment.risk_level == "high"
    
    def test_risk_score(self):
        """Test RiskScore data class"""
        risk = RiskScore(
            overall_score=7.5,
            reputation_score=6.0,
            threat_score=8.0,
            exposure_score=7.0,
            confidence=0.85,
            factors=["Domain age", "SSL certificate", "Blacklist status"],
            calculated_at=datetime.utcnow()
        )
        
        assert risk.overall_score == 7.5
        assert risk.reputation_score == 6.0
        assert risk.threat_score == 8.0
        assert risk.exposure_score == 7.0
        assert risk.confidence == 0.85
        assert len(risk.factors) == 3
        assert isinstance(risk.calculated_at, datetime)
    
    def test_risk_score_to_dict(self):
        """Test RiskScore dictionary conversion"""
        now = datetime.utcnow()
        
        risk = RiskScore(
            overall_score=5.5,
            reputation_score=4.0,
            threat_score=6.0,
            exposure_score=6.5,
            confidence=0.9,
            factors=["Recent activity", "Geographic location"],
            calculated_at=now
        )
        
        risk_dict = risk.to_dict()
        
        assert risk_dict["overall_score"] == 5.5
        assert risk_dict["reputation_score"] == 4.0
        assert risk_dict["confidence"] == 0.9
        assert risk_dict["factors"] == ["Recent activity", "Geographic location"]
        assert risk_dict["calculated_at"] == now.isoformat()


class TestDataValidation:
    """Test data validation and edge cases"""
    
    def test_empty_investigation_results(self):
        """Test handling empty investigation results"""
        results = IntelligenceResults()
        
        assert len(results.social_intelligence) == 0
        assert len(results.infrastructure_intelligence) == 0
        assert len(results.threat_intelligence) == 0
        
        all_results = results.get_all_results()
        assert len(all_results) == 0
    
    def test_invalid_confidence_scores(self):
        """Test handling invalid confidence scores"""
        # Test that confidence scores outside 0-1 range are handled
        result = IntelligenceResult(
            source="test",
            data={"test": "data"},
            confidence=1.5,  # Invalid - should be 0-1
            timestamp=datetime.utcnow()
        )
        
        # The model should store the value as-is, validation would be at application level
        assert result.confidence == 1.5
    
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
        
        # Optional fields should be None
        assert investigation.started_at is None
        assert investigation.completed_at is None
        assert investigation.processing_time_seconds is None