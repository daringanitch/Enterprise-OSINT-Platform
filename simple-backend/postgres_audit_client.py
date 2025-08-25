"""
PostgreSQL Audit Client for Enterprise OSINT Platform

This module provides database connectivity and audit logging functionality
for the Enterprise OSINT platform using PostgreSQL.
"""

import os
import json
import asyncio
import asyncpg
import psycopg2
from psycopg2.extras import RealDictCursor, Json
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict
from contextlib import contextmanager
import logging
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EventType(Enum):
    INVESTIGATION_START = "investigation_start"
    INVESTIGATION_COMPLETE = "investigation_complete"
    INVESTIGATION_ERROR = "investigation_error"
    API_KEY_CONFIGURED = "api_key_configured"
    API_KEY_ACCESSED = "api_key_accessed"
    API_CALL_MADE = "api_call_made"
    RISK_ASSESSMENT = "risk_assessment"
    COMPLIANCE_CHECK = "compliance_check"
    REPORT_GENERATED = "report_generated"
    ADMIN_ACTION = "admin_action"
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    SYSTEM_START = "system_start"
    SYSTEM_ERROR = "system_error"

@dataclass
class AuditEvent:
    """Audit event data structure"""
    event_type: EventType
    user_id: Optional[str] = None
    user_name: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    action: str = ""
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    success: bool = True
    error_message: Optional[str] = None
    request_data: Optional[Dict[str, Any]] = None
    response_data: Optional[Dict[str, Any]] = None
    processing_time_ms: Optional[int] = None
    timestamp: Optional[datetime] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)

@dataclass
class InvestigationAuditRecord:
    """Investigation audit record structure"""
    investigation_id: str
    investigator_id: str
    investigator_name: str
    target_identifier: str
    investigation_type: str
    priority: str
    status: str
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    processing_time_seconds: Optional[float] = None
    data_points_collected: int = 0
    api_calls_made: int = 0
    cost_estimate_usd: float = 0.0
    risk_score: Optional[float] = None
    threat_level: Optional[str] = None
    compliance_status: Optional[str] = None
    classification_level: Optional[str] = None
    key_findings: Optional[Dict[str, Any]] = None
    warnings: Optional[List[Dict[str, Any]]] = None
    errors: Optional[List[Dict[str, Any]]] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class APIUsageRecord:
    """API usage audit record structure"""
    service_name: str
    operation: str
    user_id: Optional[str] = None
    investigation_id: Optional[str] = None
    request_timestamp: Optional[datetime] = None
    response_time_ms: Optional[int] = None
    success: bool = True
    rate_limited: bool = False
    quota_exceeded: bool = False
    request_size: Optional[int] = None
    response_size: Optional[int] = None
    cost_usd: Optional[float] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    request_metadata: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.request_timestamp is None:
            self.request_timestamp = datetime.now(timezone.utc)

class PostgreSQLAuditClient:
    """PostgreSQL client for audit logging and data persistence"""
    
    def __init__(self, 
                 host: str = None, 
                 port: int = 5432,
                 database: str = None,
                 username: str = None,
                 password: str = None):
        """Initialize PostgreSQL audit client"""
        
        # Configuration from environment variables or defaults
        self.host = host or os.getenv('POSTGRES_HOST', 'localhost')
        self.port = port or int(os.getenv('POSTGRES_PORT', 5432))
        self.database = database or os.getenv('POSTGRES_DB', 'osint_audit')
        self.username = username or os.getenv('POSTGRES_USER', 'postgres')
        self.password = password or os.getenv('POSTGRES_PASSWORD', 'password123')
        
        self.connection_string = f"postgresql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"
        self.sync_connection_params = {
            'host': self.host,
            'port': self.port,
            'database': self.database,
            'user': self.username,
            'password': self.password
        }
        
        logger.info(f"Initialized PostgreSQL audit client for {self.host}:{self.port}/{self.database}")

    @contextmanager
    def get_connection(self):
        """Get synchronous database connection"""
        conn = None
        try:
            conn = psycopg2.connect(**self.sync_connection_params)
            conn.set_session(autocommit=False)
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database connection error: {e}")
            raise
        finally:
            if conn:
                conn.close()

    async def get_async_connection(self):
        """Get asynchronous database connection"""
        try:
            conn = await asyncpg.connect(self.connection_string)
            return conn
        except Exception as e:
            logger.error(f"Async database connection error: {e}")
            raise

    def test_connection(self) -> bool:
        """Test database connectivity"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT version();")
                    version = cursor.fetchone()
                    logger.info(f"PostgreSQL connection successful: {version[0]}")
                    return True
        except Exception as e:
            logger.error(f"PostgreSQL connection failed: {e}")
            return False

    def log_audit_event(self, event: AuditEvent) -> bool:
        """Log an audit event to the database"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    query = """
                    INSERT INTO audit.events (
                        event_type, user_id, user_name, source_ip, user_agent,
                        session_id, endpoint, method, status_code,
                        processing_time_ms, timestamp, details
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """
                    
                    # Create details JSON with all the additional info
                    details = {
                        'action': event.action,
                        'resource_type': event.resource_type,
                        'resource_id': event.resource_id, 
                        'resource_name': event.resource_name,
                        'success': event.success,
                        'error_message': event.error_message,
                        'request_data': event.request_data,
                        'response_data': event.response_data
                    }
                    
                    cursor.execute(query, (
                        event.event_type.value,
                        event.user_id,
                        event.user_name,
                        event.source_ip,
                        event.user_agent,
                        event.session_id,
                        event.endpoint if hasattr(event, 'endpoint') else None,
                        event.method if hasattr(event, 'method') else None,
                        event.status_code if hasattr(event, 'status_code') else None,
                        event.processing_time_ms,
                        event.timestamp,
                        json.dumps(details)
                    ))
                    
                    conn.commit()
                    return True
                    
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            return False

    def log_investigation_audit(self, record: InvestigationAuditRecord) -> bool:
        """Log an investigation audit record"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    query = """
                    INSERT INTO audit.investigations (
                        investigation_id, investigator_id, investigator_name,
                        target_identifier, investigation_type, priority, status,
                        created_at, started_at, completed_at, processing_time_seconds,
                        data_points_collected, api_calls_made, cost_estimate_usd,
                        risk_score, threat_level, compliance_status, classification_level,
                        key_findings, warnings, errors, metadata
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    ON CONFLICT (investigation_id)
                    DO UPDATE SET
                        status = EXCLUDED.status,
                        started_at = COALESCE(EXCLUDED.started_at, audit.investigations.started_at),
                        completed_at = EXCLUDED.completed_at,
                        processing_time_seconds = EXCLUDED.processing_time_seconds,
                        data_points_collected = EXCLUDED.data_points_collected,
                        api_calls_made = EXCLUDED.api_calls_made,
                        cost_estimate_usd = EXCLUDED.cost_estimate_usd,
                        risk_score = EXCLUDED.risk_score,
                        threat_level = EXCLUDED.threat_level,
                        compliance_status = EXCLUDED.compliance_status,
                        key_findings = EXCLUDED.key_findings,
                        warnings = EXCLUDED.warnings,
                        errors = EXCLUDED.errors,
                        metadata = EXCLUDED.metadata,
                        audit_updated_at = NOW()
                    """
                    
                    cursor.execute(query, (
                        record.investigation_id,
                        record.investigator_id,
                        record.investigator_name,
                        record.target_identifier,
                        record.investigation_type,
                        record.priority,
                        record.status,
                        record.created_at,
                        record.started_at,
                        record.completed_at,
                        record.processing_time_seconds,
                        record.data_points_collected,
                        record.api_calls_made,
                        record.cost_estimate_usd,
                        record.risk_score,
                        record.threat_level,
                        record.compliance_status,
                        record.classification_level,
                        Json(record.key_findings) if record.key_findings else None,
                        Json(record.warnings) if record.warnings else None,
                        Json(record.errors) if record.errors else None,
                        Json(record.metadata) if record.metadata else None
                    ))
                    
                    conn.commit()
                    return True
                    
        except Exception as e:
            logger.error(f"Failed to log investigation audit: {e}")
            return False

    def log_api_usage(self, record: APIUsageRecord) -> bool:
        """Log API usage record"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    query = """
                    INSERT INTO audit.api_key_usage (
                        service_name, operation, user_id, investigation_id,
                        request_timestamp, response_time_ms, success, rate_limited,
                        quota_exceeded, request_size, response_size, cost_usd,
                        error_type, error_message, request_metadata
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """
                    
                    cursor.execute(query, (
                        record.service_name,
                        record.operation,
                        record.user_id,
                        record.investigation_id,
                        record.request_timestamp,
                        record.response_time_ms,
                        record.success,
                        record.rate_limited,
                        record.quota_exceeded,
                        record.request_size,
                        record.response_size,
                        record.cost_usd,
                        record.error_type,
                        record.error_message,
                        Json(record.request_metadata) if record.request_metadata else None
                    ))
                    
                    conn.commit()
                    return True
                    
        except Exception as e:
            logger.error(f"Failed to log API usage: {e}")
            return False

    def get_investigation_activity_report(self, 
                                        start_date: Optional[datetime] = None,
                                        end_date: Optional[datetime] = None,
                                        investigator_filter: Optional[str] = None,
                                        limit: int = 1000) -> List[Dict[str, Any]]:
        """Get investigation activity report"""
        try:
            with self.get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                    
                    conditions = []
                    params = []
                    
                    if start_date:
                        conditions.append("created_at >= %s")
                        params.append(start_date)
                        
                    if end_date:
                        conditions.append("created_at <= %s")
                        params.append(end_date)
                        
                    if investigator_filter:
                        conditions.append("investigator_name ILIKE %s")
                        params.append(f"%{investigator_filter}%")
                    
                    where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
                    
                    query = f"""
                    SELECT 
                        investigation_id,
                        investigator_name,
                        target_identifier,
                        investigation_type,
                        priority,
                        status,
                        created_at,
                        completed_at,
                        processing_time_seconds,
                        risk_score,
                        threat_level,
                        data_points_collected,
                        api_calls_made,
                        cost_estimate_usd
                    FROM audit.investigations
                    {where_clause}
                    ORDER BY created_at DESC
                    LIMIT %s
                    """
                    
                    params.append(limit)
                    cursor.execute(query, params)
                    
                    results = cursor.fetchall()
                    return [dict(row) for row in results]
                    
        except Exception as e:
            logger.error(f"Failed to get investigation activity report: {e}")
            return []

    def get_api_usage_statistics(self, 
                               service_name: Optional[str] = None,
                               days_back: int = 30) -> Dict[str, Any]:
        """Get API usage statistics"""
        try:
            with self.get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                    
                    if service_name:
                        result = cursor.execute("SELECT * FROM get_api_usage_stats(%s, %s)", 
                                              (service_name, days_back))
                        stats = cursor.fetchone()
                        return dict(stats) if stats else {}
                    else:
                        # Get stats for all services
                        query = """
                        SELECT 
                            service_name,
                            COUNT(*) as total_requests,
                            COUNT(*) FILTER (WHERE success = true) as successful_requests,
                            COUNT(*) FILTER (WHERE success = false) as failed_requests,
                            ROUND(AVG(response_time_ms), 2) as avg_response_time,
                            COALESCE(SUM(cost_usd), 0) as total_cost
                        FROM audit.api_key_usage
                        WHERE request_timestamp >= NOW() - INTERVAL '%s days'
                        GROUP BY service_name
                        ORDER BY total_requests DESC
                        """
                        
                        cursor.execute(query, (days_back,))
                        results = cursor.fetchall()
                        return {row['service_name']: dict(row) for row in results}
                    
        except Exception as e:
            logger.error(f"Failed to get API usage statistics: {e}")
            return {}

    def get_investigator_performance(self, investigator_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get investigator performance metrics"""
        try:
            with self.get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                    
                    if investigator_name:
                        # Get specific investigator stats
                        cursor.execute("SELECT get_investigator_success_rate(%s) as success_rate", 
                                     (investigator_name,))
                        success_rate = cursor.fetchone()['success_rate']
                        
                        query = """
                        SELECT 
                            investigator_name,
                            COUNT(*) as total_investigations,
                            COUNT(*) FILTER (WHERE status = 'COMPLETED') as completed_investigations,
                            COUNT(*) FILTER (WHERE status = 'FAILED') as failed_investigations,
                            AVG(processing_time_seconds) as avg_processing_time,
                            AVG(risk_score) as avg_risk_score,
                            SUM(cost_estimate_usd) as total_cost,
                            %s as success_rate
                        FROM audit.investigations
                        WHERE investigator_name = %s
                        GROUP BY investigator_name
                        """
                        
                        cursor.execute(query, (success_rate, investigator_name))
                        result = cursor.fetchone()
                        return [dict(result)] if result else []
                        
                    else:
                        # Get all investigator stats
                        query = """
                        SELECT 
                            investigator_name,
                            COUNT(*) as total_investigations,
                            COUNT(*) FILTER (WHERE status = 'COMPLETED') as completed_investigations,
                            COUNT(*) FILTER (WHERE status = 'FAILED') as failed_investigations,
                            ROUND(AVG(processing_time_seconds), 2) as avg_processing_time,
                            ROUND(AVG(risk_score), 2) as avg_risk_score,
                            SUM(cost_estimate_usd) as total_cost,
                            ROUND(
                                (COUNT(*) FILTER (WHERE status = 'COMPLETED')::DECIMAL / COUNT(*)::DECIMAL) * 100, 
                                2
                            ) as success_rate
                        FROM audit.investigations
                        GROUP BY investigator_name
                        ORDER BY total_investigations DESC
                        """
                        
                        cursor.execute(query)
                        results = cursor.fetchall()
                        return [dict(row) for row in results]
                        
        except Exception as e:
            logger.error(f"Failed to get investigator performance: {e}")
            return []

    def cleanup_old_audit_data(self, days_to_keep: int = 365) -> bool:
        """Clean up old audit data beyond retention period"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    
                    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_to_keep)
                    
                    # Clean up old events
                    cursor.execute(
                        "DELETE FROM audit.events WHERE created_at < %s",
                        (cutoff_date,)
                    )
                    events_deleted = cursor.rowcount
                    
                    # Clean up old API usage records
                    cursor.execute(
                        "DELETE FROM audit.api_key_usage WHERE created_at < %s",
                        (cutoff_date,)
                    )
                    api_usage_deleted = cursor.rowcount
                    
                    # Clean up old system metrics
                    cursor.execute(
                        "DELETE FROM audit.system_metrics WHERE created_at < %s",
                        (cutoff_date,)
                    )
                    metrics_deleted = cursor.rowcount
                    
                    conn.commit()
                    
                    logger.info(f"Audit cleanup completed: {events_deleted} events, {api_usage_deleted} API usage records, {metrics_deleted} metrics deleted")
                    return True
                    
        except Exception as e:
            logger.error(f"Failed to cleanup old audit data: {e}")
            return False

# Global instance
postgres_audit_client = None

def get_audit_client() -> PostgreSQLAuditClient:
    """Get global audit client instance"""
    global postgres_audit_client
    if postgres_audit_client is None:
        postgres_audit_client = PostgreSQLAuditClient()
    return postgres_audit_client

def init_audit_client(host: str = None, 
                     port: int = 5432,
                     database: str = None,
                     username: str = None,
                     password: str = None) -> PostgreSQLAuditClient:
    """Initialize global audit client"""
    global postgres_audit_client
    postgres_audit_client = PostgreSQLAuditClient(host, port, database, username, password)
    return postgres_audit_client

# Convenience functions for common operations
def log_investigation_start(investigation_id: str, investigator_name: str, target: str, investigation_type: str, priority: str) -> bool:
    """Log investigation start event"""
    client = get_audit_client()
    
    # Log audit event
    event = AuditEvent(
        event_type=EventType.INVESTIGATION_START,
        user_name=investigator_name,
        action="CREATE",
        resource_type="investigation",
        resource_id=investigation_id,
        resource_name=target,
        success=True
    )
    
    # Log investigation record
    record = InvestigationAuditRecord(
        investigation_id=investigation_id,
        investigator_id=investigator_name.lower().replace(" ", "_"),
        investigator_name=investigator_name,
        target_identifier=target,
        investigation_type=investigation_type,
        priority=priority,
        status="STARTED",
        created_at=datetime.now(timezone.utc),
        started_at=datetime.now(timezone.utc)
    )
    
    return client.log_audit_event(event) and client.log_investigation_audit(record)

def log_investigation_complete(investigation_id: str, 
                             processing_time_seconds: float,
                             data_points: int,
                             api_calls: int,
                             cost: float,
                             risk_score: Optional[float] = None,
                             key_findings: Optional[Dict[str, Any]] = None) -> bool:
    """Log investigation completion"""
    client = get_audit_client()
    
    # Get existing record to update
    try:
        with client.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(
                    "SELECT * FROM audit.investigations WHERE investigation_id = %s",
                    (investigation_id,)
                )
                existing = cursor.fetchone()
                
                if existing:
                    record = InvestigationAuditRecord(
                        investigation_id=investigation_id,
                        investigator_id=existing['investigator_id'],
                        investigator_name=existing['investigator_name'],
                        target_identifier=existing['target_identifier'],
                        investigation_type=existing['investigation_type'],
                        priority=existing['priority'],
                        status="COMPLETED",
                        created_at=existing['created_at'],
                        started_at=existing['started_at'],
                        completed_at=datetime.now(timezone.utc),
                        processing_time_seconds=processing_time_seconds,
                        data_points_collected=data_points,
                        api_calls_made=api_calls,
                        cost_estimate_usd=cost,
                        risk_score=risk_score,
                        key_findings=key_findings
                    )
                    
                    return client.log_investigation_audit(record)
                    
    except Exception as e:
        logger.error(f"Failed to update investigation completion: {e}")
        
    return False

def log_api_call(service_name: str, 
                operation: str,
                investigation_id: Optional[str] = None,
                response_time_ms: Optional[int] = None,
                success: bool = True,
                cost_usd: Optional[float] = None,
                error_message: Optional[str] = None) -> bool:
    """Log API call usage"""
    client = get_audit_client()
    
    record = APIUsageRecord(
        service_name=service_name,
        operation=operation,
        investigation_id=investigation_id,
        response_time_ms=response_time_ms,
        success=success,
        cost_usd=cost_usd,
        error_message=error_message
    )
    
    return client.log_api_usage(record)

if __name__ == "__main__":
    # Test the audit client
    client = PostgreSQLAuditClient()
    
    if client.test_connection():
        print("PostgreSQL audit client connection successful!")
        
        # Test logging
        event = AuditEvent(
            event_type=EventType.SYSTEM_START,
            action="START",
            resource_type="system",
            success=True
        )
        
        if client.log_audit_event(event):
            print("Test audit event logged successfully!")
        else:
            print("Failed to log test audit event")
    else:
        print("PostgreSQL audit client connection failed!")