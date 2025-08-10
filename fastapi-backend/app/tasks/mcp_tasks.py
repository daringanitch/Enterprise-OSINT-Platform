"""
MCP (Model Context Protocol) tasks - placeholder
"""
from app.core.celery_app import celery_app
import structlog

logger = structlog.get_logger()


@celery_app.task(name="mcp.health_check")
def mcp_health_check():
    """Check MCP server health - placeholder"""
    logger.info("MCP health check task executed")
    return {"status": "healthy", "servers": []}