"""
Investigation models for OSINT platform
"""
from sqlalchemy import Column, String, DateTime, Text, Integer, Float, Boolean, JSON, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.base import Base
from enum import Enum
import uuid


class InvestigationStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"  
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class InvestigationType(str, Enum):
    COMPREHENSIVE = "comprehensive"
    CORPORATE = "corporate"
    INFRASTRUCTURE = "infrastructure"
    SOCIAL_MEDIA = "social_media"
    THREAT_ASSESSMENT = "threat_assessment"


class PriorityLevel(str, Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class Investigation(Base):
    __tablename__ = "investigations"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    
    # Investigation details
    target = Column(String, nullable=False, index=True)
    investigation_type = Column(String, nullable=False)
    priority = Column(String, default=PriorityLevel.NORMAL)
    description = Column(Text)
    
    # Status and progress
    status = Column(String, default=InvestigationStatus.PENDING)
    progress_percentage = Column(Integer, default=0)
    current_stage = Column(String)
    current_activity = Column(String)
    
    # Results and findings
    findings = Column(JSON, default=list)  # List of findings
    key_findings = Column(JSON, default=list)  # Important findings summary
    executive_summary = Column(Text)
    technical_details = Column(JSON, default=dict)
    
    # Risk assessment
    risk_score = Column(Float)
    threat_level = Column(String)
    confidence_level = Column(String)
    
    # Data and processing
    data_sources = Column(JSON, default=list)  # Sources used
    api_calls_made = Column(Integer, default=0)
    processing_time_seconds = Column(Float)
    data_size_mb = Column(Float, default=0.0)
    
    # Task management
    task_id = Column(String)  # Celery task ID
    workspace_id = Column(String, default="default")
    
    # Classification and compliance
    classification_level = Column(String, default="internal")  # internal, confidential, restricted
    compliance_notes = Column(Text)
    data_retention_until = Column(DateTime(timezone=True))
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    
    # Report generation
    report_generated = Column(Boolean, default=False)
    report_path = Column(String)
    report_expires_at = Column(DateTime(timezone=True))
    
    # Relationships
    user = relationship("User", back_populates="investigations")
    reports = relationship("Report", back_populates="investigation")
    
    def __repr__(self):
        return f"<Investigation {self.id}: {self.target}>"