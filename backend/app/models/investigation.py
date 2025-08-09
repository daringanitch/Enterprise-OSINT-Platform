"""
Investigation model
"""
from datetime import datetime
from sqlalchemy import Enum
import enum
import uuid

from app import db


class InvestigationType(enum.Enum):
    """Investigation types"""
    COMPREHENSIVE = "comprehensive"
    CORPORATE = "corporate"
    INFRASTRUCTURE = "infrastructure"
    SOCIAL_MEDIA = "social_media"
    THREAT_ASSESSMENT = "threat_assessment"
    

class InvestigationStatus(enum.Enum):
    """Investigation status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class InvestigationPriority(enum.Enum):
    """Investigation priority"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class Investigation(db.Model):
    """Investigation model"""
    __tablename__ = 'investigations'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, 
                     default=lambda: str(uuid.uuid4()))
    
    # Investigation details
    target = db.Column(db.String(255), nullable=False, index=True)
    type = db.Column(Enum(InvestigationType), nullable=False)
    status = db.Column(Enum(InvestigationStatus), 
                      default=InvestigationStatus.PENDING, nullable=False)
    priority = db.Column(Enum(InvestigationPriority), 
                        default=InvestigationPriority.NORMAL, nullable=False)
    
    # Scope and configuration
    scope = db.Column(db.JSON, default=dict)
    jurisdiction = db.Column(db.String(120))
    tags = db.Column(db.JSON, default=list)
    
    # Progress tracking
    progress = db.Column(db.Integer, default=0)  # 0-100
    current_step = db.Column(db.String(255))
    steps_completed = db.Column(db.JSON, default=list)
    
    # Results
    results = db.Column(db.JSON, default=dict)
    summary = db.Column(db.Text)
    threat_level = db.Column(db.String(20))  # low, medium, high, critical
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Task tracking
    celery_task_id = db.Column(db.String(255))
    
    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Relationships
    user = db.relationship('User', back_populates='investigations')
    reports = db.relationship('Report', back_populates='investigation', 
                            lazy='dynamic', cascade='all, delete-orphan')
    logs = db.relationship('InvestigationLog', back_populates='investigation',
                          lazy='dynamic', cascade='all, delete-orphan')
    
    def start(self):
        """Mark investigation as started"""
        self.status = InvestigationStatus.IN_PROGRESS
        self.started_at = datetime.utcnow()
        self.add_log("Investigation started")
    
    def complete(self, results=None, summary=None, threat_level=None):
        """Mark investigation as completed"""
        self.status = InvestigationStatus.COMPLETED
        self.completed_at = datetime.utcnow()
        self.progress = 100
        if results:
            self.results = results
        if summary:
            self.summary = summary
        if threat_level:
            self.threat_level = threat_level
        self.add_log("Investigation completed successfully")
    
    def fail(self, error=None):
        """Mark investigation as failed"""
        self.status = InvestigationStatus.FAILED
        self.completed_at = datetime.utcnow()
        self.add_log(f"Investigation failed: {error}" if error else "Investigation failed")
    
    def cancel(self):
        """Cancel investigation"""
        self.status = InvestigationStatus.CANCELLED
        self.completed_at = datetime.utcnow()
        self.add_log("Investigation cancelled by user")
    
    def update_progress(self, progress, current_step=None):
        """Update investigation progress"""
        self.progress = min(100, max(0, progress))
        if current_step:
            self.current_step = current_step
            if current_step not in self.steps_completed:
                self.steps_completed.append(current_step)
        db.session.commit()
    
    def add_log(self, message, level='info', details=None):
        """Add log entry"""
        log = InvestigationLog(
            investigation_id=self.id,
            message=message,
            level=level,
            details=details
        )
        db.session.add(log)
        db.session.commit()
    
    def to_dict(self, include_results=False):
        """Convert to dictionary"""
        data = {
            'id': self.id,
            'uuid': self.uuid,
            'target': self.target,
            'type': self.type.value,
            'status': self.status.value,
            'priority': self.priority.value,
            'scope': self.scope,
            'jurisdiction': self.jurisdiction,
            'tags': self.tags,
            'progress': self.progress,
            'current_step': self.current_step,
            'threat_level': self.threat_level,
            'summary': self.summary,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'user': {
                'id': self.user.id,
                'username': self.user.username
            }
        }
        
        if include_results:
            data['results'] = self.results
            
        return data
    
    def __repr__(self):
        return f'<Investigation {self.uuid}: {self.target}>'


class InvestigationLog(db.Model):
    """Investigation log entries"""
    __tablename__ = 'investigation_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    level = db.Column(db.String(20), default='info')  # info, warning, error
    details = db.Column(db.JSON)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Foreign keys
    investigation_id = db.Column(db.Integer, 
                                db.ForeignKey('investigations.id'), nullable=False)
    
    # Relationships
    investigation = db.relationship('Investigation', back_populates='logs')
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'message': self.message,
            'level': self.level,
            'details': self.details,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }