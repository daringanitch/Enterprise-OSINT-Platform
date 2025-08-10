"""
API v1 router
"""
from fastapi import APIRouter

from app.api.v1.endpoints import mcp, auth
from app.api.v1.endpoints import simple_investigations
from fastapi import HTTPException
from typing import Dict, Any
import uuid
import time

api_router = APIRouter()

# Include endpoint routers
api_router.include_router(
    auth.router,
    prefix="/auth",
    tags=["authentication"]
)

api_router.include_router(
    simple_investigations.router,
    prefix="/investigations",
    tags=["investigations"]
)

api_router.include_router(
    mcp.router,
    prefix="/mcp",
    tags=["mcp"]
)

# Health check at API level
@api_router.get("/health")
async def api_health():
    """API health check"""
    return {"status": "ok", "version": "v1"}

# Demo endpoints that don't require authentication
@api_router.post("/demo/investigations")
async def create_demo_investigation(request: Dict[str, Any]) -> Dict[str, Any]:
    """Demo endpoint to create investigation without authentication"""
    from app.services.osint_investigation import OSINTInvestigationService
    
    target = request.get("target", "")
    investigation_type = request.get("investigation_type", "comprehensive")
    
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")
    
    # Check if we should use real MCP or mock data
    use_real_mcp = request.get("use_real_mcp", True)
    
    if use_real_mcp:
        # Use real MCP servers
        service = OSINTInvestigationService()
        investigation = await service.run_investigation(target, investigation_type)
        investigation["message"] = "Investigation completed using MCP servers"
    else:
        # Create mock investigation (fallback)
        investigation_id = str(uuid.uuid4())
        
        investigation = {
            "id": investigation_id,
            "target": target,
            "investigation_type": investigation_type,
            "status": "processing",
            "created_at": time.time(),
            "progress": 0,
            "estimated_completion": time.time() + 300,  # 5 minutes
            "findings": {},
            "risk_score": None,
            "message": "Investigation started successfully (mock mode)"
        }
    
    return investigation

@api_router.get("/demo/investigations")
async def list_demo_investigations() -> Dict[str, Any]:
    """Demo endpoint to list investigations"""
    # Return mock investigations with consistent IDs to prevent duplicates
    investigations = [
        {
            "id": "demo-example-com-001",
            "target": "example.com",
            "investigation_type": "comprehensive",
            "status": "completed",
            "created_at": time.time() - 3600,
            "progress": 100,
            "risk_score": 75,
        },
        {
            "id": "demo-ip-192-168-1-1-001",
            "target": "192.168.1.1",
            "investigation_type": "infrastructure",
            "status": "processing",
            "created_at": time.time() - 1800,
            "progress": 45,
            "risk_score": None,
        }
    ]
    
    return {
        "investigations": investigations,
        "total": len(investigations),
        "page": 1,
        "per_page": 20
    }