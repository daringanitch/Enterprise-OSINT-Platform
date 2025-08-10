"""
API Usage model - placeholder
"""
from sqlalchemy import Column, String, DateTime, Integer, Float
from sqlalchemy.sql import func
from app.db.base import Base


class APIUsage(Base):
    __tablename__ = "api_usage"
    
    id = Column(String, primary_key=True)
    api_name = Column(String, nullable=False)
    calls_count = Column(Integer, default=0)
    cost = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())