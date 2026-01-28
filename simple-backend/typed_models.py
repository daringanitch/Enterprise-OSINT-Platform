#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.
# Individual use is free. Commercial use requires 3% profit sharing.
# See LICENSE file for details.

"""
Typed Pydantic Models for Enterprise OSINT Platform

Provides type-safe models for:
- API responses with automatic serialization
- Intelligence data structures
- Investigation results
- MCP server responses

Benefits:
- Type safety and IDE autocompletion
- Automatic validation
- Self-documenting API responses
- Consistent data structures
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime
from enum import Enum


# ============================================================================
# Enums for Type Safety
# ============================================================================

class InvestigationStatusEnum(str, Enum):
    PENDING = "pending"
    QUEUED = "queued"
    PLANNING = "planning"
    PROFILING = "profiling"
    COLLECTING = "collecting"
    ANALYZING = "analyzing"
    ASSESSING_RISK = "assessing_risk"
    VERIFYING = "verifying"
    GENERATING_REPORT = "generating_report"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PriorityEnum(str, Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"
    CRITICAL = "critical"


class RiskLevelEnum(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatLevelEnum(str, Enum):
    MINIMAL = "minimal"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


# ============================================================================
# Infrastructure Intelligence Models
# ============================================================================

class WHOISData(BaseModel):
    """WHOIS lookup result with typed fields"""
    model_config = ConfigDict(extra='allow')

    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    status: List[str] = Field(default_factory=list)
    name_servers: List[str] = Field(default_factory=list)
    organization: Optional[str] = None
    country: Optional[str] = None
    registrant_email: Optional[str] = None
    admin_email: Optional[str] = None
    dnssec: Optional[str] = None


class DNSRecord(BaseModel):
    """Individual DNS record"""
    record_type: str
    value: str
    ttl: Optional[int] = None


class DNSData(BaseModel):
    """DNS lookup results with typed fields"""
    model_config = ConfigDict(extra='allow')

    domain: str
    a_records: List[str] = Field(default_factory=list)
    aaaa_records: List[str] = Field(default_factory=list)
    mx_records: List[str] = Field(default_factory=list)
    ns_records: List[str] = Field(default_factory=list)
    txt_records: List[str] = Field(default_factory=list)
    cname_records: List[str] = Field(default_factory=list)
    soa_record: Optional[str] = None
    query_time_ms: Optional[float] = None


class SSLCertificateData(BaseModel):
    """SSL certificate information"""
    model_config = ConfigDict(extra='allow')

    domain: str
    issuer: Dict[str, str] = Field(default_factory=dict)
    subject: Dict[str, str] = Field(default_factory=dict)
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    serial_number: Optional[str] = None
    signature_algorithm: Optional[str] = None
    is_valid: bool = False
    days_until_expiry: int = 0
    san_domains: List[str] = Field(default_factory=list)


class IPAddressInfo(BaseModel):
    """IP address information"""
    ip: str
    version: Literal["ipv4", "ipv6"] = "ipv4"
    reverse_dns: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    is_private: bool = False


class ExposedService(BaseModel):
    """Exposed network service"""
    port: int
    protocol: str = "tcp"
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    is_vulnerable: bool = False
    vulnerabilities: List[str] = Field(default_factory=list)


class InfrastructureIntelligenceResponse(BaseModel):
    """Complete infrastructure intelligence response"""
    model_config = ConfigDict(extra='allow')

    target: str
    whois: Optional[WHOISData] = None
    dns: Optional[DNSData] = None
    ssl_certificate: Optional[SSLCertificateData] = None
    ip_addresses: List[IPAddressInfo] = Field(default_factory=list)
    exposed_services: List[ExposedService] = Field(default_factory=list)
    subdomains: List[str] = Field(default_factory=list)
    risk_score: float = 0.0
    data_freshness: Optional[str] = None
    collected_at: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# Threat Intelligence Models
# ============================================================================

class ThreatIndicator(BaseModel):
    """Individual threat indicator"""
    indicator_type: Literal["domain", "ip", "hash", "url", "email"]
    value: str
    threat_type: Optional[str] = None
    confidence: float = 0.0
    severity: RiskLevelEnum = RiskLevelEnum.LOW
    source: str = "unknown"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class VirusTotalResult(BaseModel):
    """VirusTotal scan result"""
    model_config = ConfigDict(extra='allow')

    target: str
    scan_date: Optional[str] = None
    malicious_detections: int = 0
    suspicious_detections: int = 0
    clean_detections: int = 0
    total_scanners: int = 0
    threat_score: float = 0.0
    reputation: int = 0
    categories: Dict[str, str] = Field(default_factory=dict)
    last_analysis_stats: Dict[str, int] = Field(default_factory=dict)


class ThreatIntelligenceResponse(BaseModel):
    """Complete threat intelligence response"""
    model_config = ConfigDict(extra='allow')

    target: str
    threat_level: ThreatLevelEnum = ThreatLevelEnum.MINIMAL
    risk_score: float = 0.0
    confidence: float = 0.0
    indicators: List[ThreatIndicator] = Field(default_factory=list)
    virustotal: Optional[VirusTotalResult] = None
    malware_detected: bool = False
    phishing_detected: bool = False
    spam_detected: bool = False
    recommendations: List[str] = Field(default_factory=list)
    sources_queried: List[str] = Field(default_factory=list)
    collected_at: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# Social Intelligence Models
# ============================================================================

class SocialMediaProfile(BaseModel):
    """Social media profile information"""
    platform: str
    username: Optional[str] = None
    display_name: Optional[str] = None
    bio: Optional[str] = None
    followers: int = 0
    following: int = 0
    posts_count: int = 0
    verified: bool = False
    profile_url: Optional[str] = None
    created_at: Optional[str] = None
    location: Optional[str] = None


class SentimentAnalysis(BaseModel):
    """Sentiment analysis result"""
    overall_score: float = 0.0  # -1.0 to 1.0
    positive_ratio: float = 0.0
    negative_ratio: float = 0.0
    neutral_ratio: float = 0.0
    sample_size: int = 0


class SocialIntelligenceResponse(BaseModel):
    """Complete social intelligence response"""
    model_config = ConfigDict(extra='allow')

    target: str
    profiles: List[SocialMediaProfile] = Field(default_factory=list)
    sentiment: Optional[SentimentAnalysis] = None
    reputation_score: float = 50.0  # 0-100 scale
    total_mentions: int = 0
    platforms_found: List[str] = Field(default_factory=list)
    risk_indicators: List[str] = Field(default_factory=list)
    collected_at: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# Investigation Models
# ============================================================================

class InvestigationProgress(BaseModel):
    """Investigation progress information"""
    stage: InvestigationStatusEnum = InvestigationStatusEnum.PENDING
    stage_progress: float = 0.0
    overall_progress: float = 0.0
    current_activity: str = ""
    estimated_completion: Optional[str] = None
    data_points_collected: int = 0
    errors_encountered: int = 0
    warnings: List[str] = Field(default_factory=list)


class TargetProfile(BaseModel):
    """Investigation target profile"""
    target_id: str
    target_type: Literal["domain", "company", "individual", "ip_address", "email"]
    primary_identifier: str
    secondary_identifiers: List[str] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    """Risk assessment result"""
    overall_score: float = 0.0
    risk_level: RiskLevelEnum = RiskLevelEnum.LOW
    social_risk: float = 0.0
    infrastructure_risk: float = 0.0
    threat_risk: float = 0.0
    compliance_risk: float = 0.0
    confidence: float = 0.0
    factors: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)


class InvestigationSummary(BaseModel):
    """Investigation summary for list views"""
    model_config = ConfigDict(extra='allow')

    id: str
    target: str
    target_type: str = "domain"
    status: InvestigationStatusEnum
    investigation_type: str = "comprehensive"
    priority: PriorityEnum = PriorityEnum.NORMAL
    progress_percentage: int = 0
    investigator_name: str = "System"
    created_at: str
    completed_at: Optional[str] = None
    risk_level: Optional[RiskLevelEnum] = None
    can_generate_report: bool = False


class InvestigationDetail(BaseModel):
    """Detailed investigation response"""
    model_config = ConfigDict(extra='allow')

    id: str
    target_profile: TargetProfile
    status: InvestigationStatusEnum
    investigation_type: str
    priority: PriorityEnum
    progress: InvestigationProgress
    investigator_id: str = "system"
    investigator_name: str = "System"
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    classification_level: str = "confidential"

    # Intelligence results
    infrastructure_intelligence: Optional[Dict[str, Any]] = None
    social_intelligence: Optional[Dict[str, Any]] = None
    threat_intelligence: Optional[Dict[str, Any]] = None

    # Assessment
    risk_assessment: Optional[RiskAssessment] = None
    key_findings: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    executive_summary: str = ""

    # Metadata
    api_calls_made: int = 0
    data_size_mb: float = 0.0
    processing_time_seconds: float = 0.0
    cost_estimate_usd: float = 0.0


# ============================================================================
# API Response Models
# ============================================================================

class APIResponse(BaseModel):
    """Standard API response wrapper"""
    success: bool = True
    data: Optional[Any] = None
    error: Optional[str] = None
    message: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    cached: bool = False


class PaginatedResponse(BaseModel):
    """Paginated API response"""
    items: List[Any]
    total: int
    page: int = 1
    per_page: int = 20
    pages: int = 1
    has_next: bool = False
    has_prev: bool = False


class HealthResponse(BaseModel):
    """Health check response"""
    service: str
    status: Literal["healthy", "degraded", "unhealthy"]
    timestamp: datetime
    version: Optional[str] = None
    components: Dict[str, str] = Field(default_factory=dict)


class MCPServerStatus(BaseModel):
    """MCP server status"""
    name: str
    status: Literal["healthy", "degraded", "unhealthy", "unknown"]
    response_time_ms: Optional[float] = None
    last_check: Optional[str] = None
    capabilities: List[str] = Field(default_factory=list)
    demo_mode: bool = False


class SystemStatusResponse(BaseModel):
    """System status response"""
    service: str = "Enterprise OSINT Platform"
    status: Literal["operational", "degraded", "outage"]
    mode: Literal["production", "demo", "maintenance"]
    mcp_servers: Dict[str, MCPServerStatus] = Field(default_factory=dict)
    database: Dict[str, Any] = Field(default_factory=dict)
    cache: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# Compliance Models
# ============================================================================

class ComplianceFinding(BaseModel):
    """Individual compliance finding"""
    category: str
    status: Literal["compliant", "non_compliant", "requires_review"]
    details: str
    severity: RiskLevelEnum = RiskLevelEnum.LOW
    recommendation: Optional[str] = None


class ComplianceAssessmentResponse(BaseModel):
    """Compliance assessment response"""
    assessment_id: str
    framework: str
    status: Literal["compliant", "non_compliant", "requires_review"]
    compliance_score: float = 0.0
    risk_level: RiskLevelEnum = RiskLevelEnum.LOW
    findings: List[ComplianceFinding] = Field(default_factory=list)
    data_categories: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    assessed_at: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# Report Models
# ============================================================================

class ReportMetadata(BaseModel):
    """Report metadata"""
    report_id: str
    investigation_id: str
    report_type: str = "comprehensive"
    format: Literal["json", "pdf", "markdown", "html"] = "pdf"
    classification: str = "confidential"
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    generated_by: str = "system"
    file_size_bytes: Optional[int] = None
    expires_at: Optional[datetime] = None


class ReportResponse(BaseModel):
    """Report generation response"""
    success: bool
    report: Optional[ReportMetadata] = None
    download_url: Optional[str] = None
    error: Optional[str] = None


# ============================================================================
# Helper Functions
# ============================================================================

def serialize_investigation(investigation) -> InvestigationSummary:
    """Convert investigation dataclass to typed model"""
    return InvestigationSummary(
        id=investigation.id,
        target=investigation.target_profile.primary_identifier,
        target_type=investigation.target_profile.target_type,
        status=InvestigationStatusEnum(investigation.status.value),
        investigation_type=investigation.investigation_type.value,
        priority=PriorityEnum(investigation.priority.value),
        progress_percentage=investigation.get_overall_progress_percentage(),
        investigator_name=investigation.investigator_name,
        created_at=investigation.created_at.isoformat() if investigation.created_at else None,
        completed_at=investigation.completed_at.isoformat() if investigation.completed_at else None,
        risk_level=RiskLevelEnum(investigation.risk_assessment.get('risk_level', 'low')) if investigation.risk_assessment else None,
        can_generate_report=investigation.status.value == 'completed'
    )


def serialize_whois(data: dict) -> WHOISData:
    """Convert raw WHOIS dict to typed model"""
    return WHOISData(
        domain=data.get('domain', ''),
        registrar=data.get('registrar'),
        creation_date=data.get('creation_date') or data.get('created'),
        expiration_date=data.get('expiration_date') or data.get('expires'),
        updated_date=data.get('updated_date') or data.get('updated'),
        status=data.get('status', []) if isinstance(data.get('status'), list) else [data.get('status', '')],
        name_servers=data.get('name_servers', []) or data.get('nameservers', []),
        organization=data.get('organization') or data.get('org'),
        country=data.get('country'),
        registrant_email=data.get('registrant_email'),
        admin_email=data.get('admin_email'),
        dnssec=data.get('dnssec')
    )


def serialize_dns(data: dict) -> DNSData:
    """Convert raw DNS dict to typed model"""
    records = data.get('records', {})
    return DNSData(
        domain=data.get('domain', ''),
        a_records=records.get('A', []) or [data.get('a_record')] if data.get('a_record') else [],
        aaaa_records=records.get('AAAA', []),
        mx_records=records.get('MX', []) or data.get('mx_records', []),
        ns_records=records.get('NS', []) or data.get('ns_records', []),
        txt_records=records.get('TXT', []) or data.get('txt_records', []),
        cname_records=records.get('CNAME', []) or data.get('cname_records', []),
        soa_record=records.get('SOA', [None])[0] if records.get('SOA') else None,
        query_time_ms=data.get('query_time_ms')
    )
