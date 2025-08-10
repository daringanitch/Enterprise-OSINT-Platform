"""
Pydantic schemas for investigations
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, validator
from enum import Enum


class InvestigationType(str, Enum):
    DOMAIN = "domain"
    INFRASTRUCTURE = "infrastructure"
    PERSON = "person"
    SOCIAL = "social"
    THREAT = "threat"
    ALL = "all"


class InvestigationStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class InvestigationBase(BaseModel):
    """Base investigation schema"""
    target: str = Field(..., min_length=1, max_length=500, description="Investigation target")
    investigation_type: InvestigationType = Field(..., description="Type of investigation")
    description: Optional[str] = Field(None, max_length=2000, description="Investigation description")
    tags: Optional[List[str]] = Field(default_factory=list, description="Investigation tags")
    priority: Optional[int] = Field(1, ge=1, le=5, description="Priority (1-5)")
    
    @validator("target")
    def validate_target(cls, v):
        """Validate and sanitize target"""
        return v.strip().lower()
    
    @validator("tags")
    def validate_tags(cls, v):
        """Ensure unique tags"""
        return list(set(v)) if v else []


class InvestigationCreate(InvestigationBase):
    """Schema for creating investigations"""
    notify_email: Optional[str] = Field(None, description="Email for completion notification")
    max_depth: Optional[int] = Field(2, ge=1, le=5, description="Maximum investigation depth")
    include_screenshots: Optional[bool] = Field(False, description="Include screenshots in report")


class InvestigationUpdate(BaseModel):
    """Schema for updating investigations"""
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    priority: Optional[int] = Field(None, ge=1, le=5)
    status: Optional[InvestigationStatus] = None


class InvestigationInDB(InvestigationBase):
    """Schema for investigations in database"""
    id: str
    status: InvestigationStatus
    user_id: str
    created_at: datetime
    updated_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    task_id: Optional[str] = None
    
    class Config:
        orm_mode = True


class InvestigationResponse(InvestigationInDB):
    """Schema for investigation API responses"""
    progress: Optional[int] = Field(0, ge=0, le=100, description="Progress percentage")
    estimated_completion: Optional[datetime] = None
    data_sources_completed: Optional[int] = 0
    data_sources_total: Optional[int] = 0
    risk_score: Optional[float] = Field(None, ge=0, le=100)
    report_available: bool = False
    report_id: Optional[str] = None


class InvestigationListResponse(BaseModel):
    """Schema for investigation list responses"""
    total: int
    page: int
    per_page: int
    pages: int
    items: List[InvestigationResponse]


class InvestigationDataPoint(BaseModel):
    """Schema for individual data points collected"""
    source: str
    timestamp: datetime
    data_type: str
    confidence: float = Field(..., ge=0, le=1)
    data: Dict[str, Any]
    metadata: Optional[Dict[str, Any]] = None


class InvestigationSummary(BaseModel):
    """Schema for investigation summary"""
    id: str
    target: str
    type: InvestigationType
    status: InvestigationStatus
    created_at: datetime
    risk_score: Optional[float] = None
    key_findings: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)


class BulkInvestigationCreate(BaseModel):
    """Schema for creating multiple investigations"""
    targets: List[str] = Field(..., min_items=1, max_items=100)
    investigation_type: InvestigationType
    common_tags: Optional[List[str]] = Field(default_factory=list)
    priority: Optional[int] = Field(1, ge=1, le=5)
    
    @validator("targets")
    def validate_unique_targets(cls, v):
        """Ensure targets are unique"""
        unique_targets = list(set(target.strip().lower() for target in v))
        if len(unique_targets) != len(v):
            raise ValueError("Duplicate targets found")
        return unique_targets


class InvestigationExport(BaseModel):
    """Schema for exporting investigation data"""
    format: str = Field("json", regex="^(json|csv|pdf|html)$")
    include_raw_data: bool = False
    include_screenshots: bool = False
    sections: Optional[List[str]] = Field(
        default_factory=lambda: ["summary", "findings", "recommendations", "timeline"]
    )