"""
Simple OSINT tasks for testing Celery functionality
"""
from typing import Dict, Any
import time
import structlog
from app.core.celery_app import celery_app

logger = structlog.get_logger()


@celery_app.task(name="osint.test_task")
def test_task(message: str = "Hello from Celery!") -> Dict[str, Any]:
    """
    Simple test task to verify Celery is working
    """
    logger.info("Test task started", message=message)
    time.sleep(2)  # Simulate some work
    
    result = {
        "status": "completed",
        "message": message,
        "timestamp": time.time()
    }
    
    logger.info("Test task completed", result=result)
    return result


@celery_app.task(name="osint.investigate_target_simple")
def investigate_target_simple(investigation_id: str, target: str, investigation_type: str) -> Dict[str, Any]:
    """
    Simple investigation task - placeholder implementation
    """
    logger.info(
        "Starting simple investigation",
        investigation_id=investigation_id,
        target=target,
        type=investigation_type
    )
    
    # Simulate investigation work
    time.sleep(5)
    
    # Mock results
    mock_results = {
        "dns_data": {"A": ["127.0.0.1"], "status": "resolved"},
        "whois_data": {"registrar": "Mock Registrar", "status": "found"},
        "risk_assessment": {"score": 25, "level": "low"}
    }
    
    result = {
        "investigation_id": investigation_id,
        "target": target,
        "type": investigation_type,
        "status": "completed",
        "results": mock_results,
        "timestamp": time.time()
    }
    
    logger.info("Investigation completed", result=result)
    return result


@celery_app.task(name="osint.update_api_usage_metrics")
def update_api_usage_metrics() -> Dict[str, Any]:
    """
    Simple API usage metrics update task
    """
    logger.info("Updating API usage metrics")
    
    # Mock metrics calculation
    metrics = {
        "total_calls": 42,
        "total_cost": 1.23,
        "updated_at": time.time()
    }
    
    logger.info("API usage metrics updated", metrics=metrics)
    return metrics