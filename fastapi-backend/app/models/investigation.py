"""
Investigation models - placeholder
"""
from sqlalchemy import Column, String, DateTime, Text, Integer
from sqlalchemy.sql import func
from app.db.base import Base
from enum import Enum


class InvestigationStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Investigation(Base):
    __tablename__ = "investigations"
    
    id = Column(String, primary_key=True)
    target = Column(String, nullable=False)
    investigation_type = Column(String, nullable=False)
    status = Column(String, default="pending")
    user_id = Column(String, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    task_id = Column(String)