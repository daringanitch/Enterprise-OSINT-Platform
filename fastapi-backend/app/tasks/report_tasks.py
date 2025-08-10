"""
Report generation tasks - placeholder
"""
from app.core.celery_app import celery_app
import structlog

logger = structlog.get_logger()


@celery_app.task(name="reports.cleanup_old_reports")
def cleanup_old_reports():
    """Clean up old reports - placeholder"""
    logger.info("Cleanup old reports task executed")
    return {"status": "completed", "cleaned": 0}