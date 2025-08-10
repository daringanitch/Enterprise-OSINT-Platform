"""
Audit log model - placeholder
"""
from sqlalchemy import Column, String, DateTime, Text
from sqlalchemy.sql import func
from app.db.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(String, primary_key=True)
    action = Column(String, nullable=False)
    details = Column(Text)
    user_id = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())