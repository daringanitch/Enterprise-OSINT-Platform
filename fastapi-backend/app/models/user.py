"""
User model with authentication support
"""
from sqlalchemy import Column, String, Boolean, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.base import Base
import uuid


class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=True)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    is_verified = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    
    # Profile settings
    avatar_url = Column(String, nullable=True)
    organization = Column(String, nullable=True)
    timezone = Column(String, default="UTC")
    
    # Investigation limits
    max_concurrent_investigations = Column(String, default="10")  # Can be overridden per user
    investigation_quota_per_day = Column(String, default="50")
    
    # Email verification
    verification_token = Column(String, nullable=True)
    verification_token_expires = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    # investigations = relationship("Investigation", back_populates="user")
    # audit_events = relationship("AuditEvent", back_populates="user")
    
    def __repr__(self):
        return f"<User {self.email}>"