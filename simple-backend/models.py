#!/usr/bin/env python3
"""
OSINT Investigation Models and Data Structures
Based on the original enterprise OSINT agent architecture
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Literal
from datetime import datetime, timedelta
from enum import Enum
import json
import uuid


class InvestigationType(Enum):
    COMPREHENSIVE = "comprehensive"
    CORPORATE = "corporate" 
    INFRASTRUCTURE = "infrastructure"
    SOCIAL_MEDIA = "social_media"
    THREAT_ASSESSMENT = "threat_assessment"
    COMPLIANCE_CHECK = "compliance_check"


class InvestigationStatus(Enum):
    PENDING = "pending"
    PLANNING = "planning"
    PROFILING = "profiling"
    COLLECTING = "collecting"
    ANALYZING = "analyzing"
    VERIFYING = "verifying"
    GENERATING_REPORT = "generating_report"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Priority(Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"
    CRITICAL = "critical"


class ComplianceFramework(Enum):
    GDPR = "gdpr"
    CCPA = "ccpa"
    PIPEDA = "pipeda"
    LGPD = "lgpd"


@dataclass
class TargetProfile:
    """Target entity profiling and scoping information"""
    target_id: str
    target_type: Literal["domain", "company", "individual", "ip_address", "email"]
    primary_identifier: str
    secondary_identifiers: List[str] = field(default_factory=list)
    scope_restrictions: Dict[str, Any] = field(default_factory=dict)
    compliance_requirements: List[ComplianceFramework] = field(default_factory=list)
    geographic_scope: List[str] = field(default_factory=list)  # ISO country codes
    data_retention_days: int = 30
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class InvestigationScope:
    """Investigation parameters and data collection constraints"""
    include_social_media: bool = True
    include_infrastructure: bool = True
    include_threat_intelligence: bool = True
    include_corporate_records: bool = True
    include_public_records: bool = True
    
    # Data collection limits
    max_social_posts: int = 1000
    max_domains_to_scan: int = 100
    max_threat_indicators: int = 500
    
    # Time constraints
    historical_data_days: int = 90
    max_investigation_hours: int = 24
    
    # Compliance constraints
    exclude_pii: bool = True
    exclude_protected_categories: bool = True
    require_consent_verification: bool = False


@dataclass
class IntelligenceSource:
    """Individual intelligence data source information"""
    source_id: str
    source_type: Literal["social_media", "infrastructure", "threat_intel", "public_records"]
    api_endpoint: str
    last_updated: datetime
    data_quality_score: float = 0.0
    reliability_score: float = 0.0
    data_points_collected: int = 0
    errors_encountered: List[str] = field(default_factory=list)


@dataclass
class SocialIntelligence:
    """Social media and public presence intelligence data"""
    platforms: Dict[str, Dict] = field(default_factory=dict)  # platform_name -> data
    sentiment_analysis: Dict[str, float] = field(default_factory=dict)
    engagement_metrics: Dict[str, Any] = field(default_factory=dict)
    reputation_score: float = 0.0
    threat_indicators: List[str] = field(default_factory=list)
    last_activity: Optional[datetime] = None
    data_sources: List[IntelligenceSource] = field(default_factory=list)


@dataclass
class InfrastructureIntelligence:
    """Network and domain infrastructure intelligence"""
    domains: List[Dict] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    ip_addresses: List[Dict] = field(default_factory=list)
    certificates: List[Dict] = field(default_factory=list)
    dns_records: Dict[str, List] = field(default_factory=dict)
    exposed_services: List[Dict] = field(default_factory=list)
    network_topology: Dict[str, Any] = field(default_factory=dict)
    risk_indicators: List[str] = field(default_factory=list)
    data_sources: List[IntelligenceSource] = field(default_factory=list)


@dataclass
class ThreatIntelligence:
    """Threat indicators and risk assessment data"""
    malware_indicators: List[Dict] = field(default_factory=list)
    network_indicators: List[Dict] = field(default_factory=list)
    behavioral_indicators: List[Dict] = field(default_factory=list)
    threat_actors: List[Dict] = field(default_factory=list)
    campaigns: List[Dict] = field(default_factory=list)
    risk_score: float = 0.0
    confidence_level: float = 0.0
    mitre_techniques: List[str] = field(default_factory=list)
    data_sources: List[IntelligenceSource] = field(default_factory=list)


@dataclass
class ComplianceReport:
    """GDPR/CCPA compliance analysis results"""
    framework: ComplianceFramework
    compliant: bool
    risk_level: Literal["low", "medium", "high", "critical"]
    findings: List[Dict] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    data_categories_identified: List[str] = field(default_factory=list)
    retention_compliance: bool = True
    consent_status: Optional[str] = None
    generated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class InvestigationProgress:
    """Real-time investigation progress tracking"""
    stage: InvestigationStatus
    stage_progress: float = 0.0  # 0.0 to 1.0
    overall_progress: float = 0.0  # 0.0 to 1.0
    current_activity: str = ""
    estimated_completion: Optional[datetime] = None
    data_points_collected: int = 0
    errors_encountered: int = 0
    warnings: List[str] = field(default_factory=list)
    last_updated: datetime = field(default_factory=datetime.utcnow)


@dataclass
class OSINTInvestigation:
    """Complete OSINT investigation record"""
    
    # Core identification
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    workspace_id: str = "default"
    
    # Investigation metadata
    target_profile: TargetProfile = field(default_factory=lambda: TargetProfile("", "domain", ""))
    investigation_type: InvestigationType = InvestigationType.COMPREHENSIVE
    scope: InvestigationScope = field(default_factory=InvestigationScope)
    priority: Priority = Priority.NORMAL
    
    # Status and progress
    status: InvestigationStatus = InvestigationStatus.PENDING
    progress: InvestigationProgress = field(default_factory=InvestigationProgress)
    
    # User and audit information
    investigator_id: str = "system"
    investigator_name: str = "System"
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Intelligence data
    social_intelligence: Optional[SocialIntelligence] = None
    infrastructure_intelligence: Optional[InfrastructureIntelligence] = None
    threat_intelligence: Optional[ThreatIntelligence] = None
    
    # Compliance and security
    compliance_reports: List[ComplianceReport] = field(default_factory=list)
    classification_level: Literal["public", "internal", "confidential", "restricted"] = "confidential"
    data_retention_until: Optional[datetime] = None
    
    # Results and reporting
    key_findings: List[str] = field(default_factory=list)
    risk_assessment: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    executive_summary: str = ""
    
    # Technical metadata
    api_calls_made: int = 0
    data_size_mb: float = 0.0
    processing_time_seconds: float = 0.0
    cost_estimate_usd: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert investigation to dictionary for API responses"""
        def serialize_datetime(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            return obj
            
        def convert_dataclass(obj):
            if hasattr(obj, '__dict__'):
                return {k: serialize_datetime(v) if isinstance(v, datetime) 
                       else convert_dataclass(v) if hasattr(v, '__dict__')
                       else v for k, v in obj.__dict__.items()}
            return obj
            
        return convert_dataclass(self)
    
    def get_stage_progress_percentage(self) -> int:
        """Get current stage progress as percentage"""
        return int(self.progress.stage_progress * 100)
    
    def get_overall_progress_percentage(self) -> int:
        """Get overall investigation progress as percentage"""
        return int(self.progress.overall_progress * 100)
    
    def is_expired(self) -> bool:
        """Check if investigation data has expired based on retention policy"""
        if not self.data_retention_until:
            return False
        return datetime.utcnow() > self.data_retention_until
    
    def get_estimated_time_remaining(self) -> Optional[timedelta]:
        """Calculate estimated time remaining for investigation"""
        if not self.progress.estimated_completion:
            return None
        return self.progress.estimated_completion - datetime.utcnow()
    
    def add_finding(self, finding: str, category: str = "general"):
        """Add a new finding to the investigation"""
        timestamp = datetime.utcnow().isoformat()
        self.key_findings.append(f"[{category.upper()}] {finding} (discovered: {timestamp})")
    
    def update_progress(self, stage_progress: float, activity: str = ""):
        """Update investigation progress"""
        self.progress.stage_progress = min(1.0, max(0.0, stage_progress))
        if activity:
            self.progress.current_activity = activity
        self.progress.last_updated = datetime.utcnow()
        
        # Calculate overall progress based on stage
        stage_weights = {
            InvestigationStatus.PENDING: 0.0,
            InvestigationStatus.PLANNING: 0.1,
            InvestigationStatus.PROFILING: 0.2,
            InvestigationStatus.COLLECTING: 0.6,  # Major portion
            InvestigationStatus.ANALYZING: 0.8,
            InvestigationStatus.VERIFYING: 0.9,
            InvestigationStatus.GENERATING_REPORT: 0.95,
            InvestigationStatus.COMPLETED: 1.0
        }
        
        base_progress = stage_weights.get(self.status, 0.0)
        stage_contribution = (stage_weights.get(self.status, 0.0) - 
                            (0.1 if self.status != InvestigationStatus.PENDING else 0.0)) * stage_progress
        self.progress.overall_progress = min(1.0, base_progress + stage_contribution)


@dataclass 
class WorkspaceSettings:
    """Multi-tenant workspace configuration"""
    workspace_id: str
    name: str
    organization: str
    max_concurrent_investigations: int = 10
    data_retention_days: int = 30
    api_rate_limits: Dict[str, int] = field(default_factory=dict)
    enabled_intelligence_sources: List[str] = field(default_factory=list)
    compliance_frameworks: List[ComplianceFramework] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)


class InvestigationError(Exception):
    """Custom exception for investigation-related errors"""
    
    def __init__(self, message: str, investigation_id: str = None, error_code: str = None):
        self.message = message
        self.investigation_id = investigation_id
        self.error_code = error_code
        super().__init__(message)