"""
Report model for generated investigation reports
"""
from sqlalchemy import Column, String, DateTime, Text, Integer, Float, Boolean, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.base import Base
from enum import Enum
import uuid


class ReportFormat(str, Enum):
    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    DOCX = "docx"


class ReportType(str, Enum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    COMPLIANCE = "compliance" 
    FULL = "full"


class Report(Base):
    __tablename__ = "reports"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(String, ForeignKey("investigations.id"), nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    
    # Report details
    title = Column(String, nullable=False)
    report_type = Column(String, default=ReportType.FULL)
    format = Column(String, default=ReportFormat.PDF)
    
    # Content
    content = Column(Text)  # HTML or markdown content
    executive_summary = Column(Text)
    findings_summary = Column(Text)
    recommendations = Column(Text)
    
    # File information
    file_path = Column(String)  # Path to generated file
    file_size_bytes = Column(Integer)
    file_hash = Column(String)  # SHA256 hash for integrity
    
    # Access and security
    download_count = Column(Integer, default=0)
    password_protected = Column(Boolean, default=False)
    watermarked = Column(Boolean, default=True)
    classification_level = Column(String, default="internal")
    
    # Expiration
    expires_at = Column(DateTime(timezone=True))
    auto_delete = Column(Boolean, default=True)
    
    # Generation metadata
    generation_time_seconds = Column(Float)
    template_version = Column(String)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_accessed_at = Column(DateTime(timezone=True))
    
    # Relationships
    investigation = relationship("Investigation", back_populates="reports")
    user = relationship("User")
    
    def __repr__(self):
        return f"<Report {self.id}: {self.title}>"