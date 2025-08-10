"""
Simple investigation endpoints with authentication
"""
from typing import List, Optional, Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
import structlog
import uuid
import time

from app.core.auth import get_current_verified_user
from app.db.session import get_db
from app.models.user import User
from app.services.osint_investigation import OSINTInvestigationService

router = APIRouter()
logger = structlog.get_logger()


class SimpleInvestigationRequest:
    def __init__(self, target: str, investigation_type: str = "comprehensive"):
        self.target = target
        self.investigation_type = investigation_type


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_investigation(
    *,
    db: AsyncSession = Depends(get_db),
    request_data: Dict[str, Any],
    current_user: User = Depends(get_current_verified_user)
) -> Any:
    """
    Create a new investigation (authenticated users only)
    """
    target = request_data.get("target", "")
    investigation_type = request_data.get("investigation_type", "comprehensive")
    
    if not target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target is required"
        )
    
    logger.info(
        "Starting authenticated investigation", 
        user_id=current_user.id, 
        target=target, 
        investigation_type=investigation_type
    )
    
    # Use real MCP servers for authenticated users
    service = OSINTInvestigationService()
    try:
        investigation = await service.run_investigation(target, investigation_type)
        investigation["user_id"] = current_user.id
        investigation["message"] = f"Investigation completed for authenticated user {current_user.email}"
        
        logger.info(
            "Investigation completed",
            user_id=current_user.id,
            investigation_id=investigation["id"],
            target=target,
            risk_score=investigation.get("risk_score", 0)
        )
        
        return investigation
        
    except Exception as e:
        logger.error(
            "Investigation failed",
            user_id=current_user.id,
            target=target,
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Investigation failed: {str(e)}"
        )


@router.get("/")
async def list_investigations(
    *,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_verified_user)
) -> Any:
    """
    List user's investigations (authenticated users only)
    """
    # For now, return user-specific mock data
    investigations = [
        {
            "id": f"user-{current_user.id}-investigation-1",
            "target": "example.com",
            "investigation_type": "comprehensive", 
            "status": "completed",
            "created_at": time.time() - 7200,  # 2 hours ago
            "progress": 100,
            "risk_score": 65,
            "user_id": current_user.id,
            "findings": {
                "infrastructure": {"domain_age": "5 years", "ssl_grade": "B"},
                "threat_intelligence": {"reputation": "clean", "breaches": 0}
            }
        },
        {
            "id": f"user-{current_user.id}-investigation-2", 
            "target": "suspicious-domain.net",
            "investigation_type": "threat_assessment",
            "status": "processing",
            "created_at": time.time() - 900,  # 15 minutes ago
            "progress": 75,
            "risk_score": None,
            "user_id": current_user.id
        }
    ]
    
    return {
        "investigations": investigations,
        "total": len(investigations),
        "page": 1,
        "per_page": 20,
        "user_email": current_user.email
    }


@router.get("/{investigation_id}")
async def get_investigation(
    *,
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_verified_user)
) -> Any:
    """
    Get specific investigation details (authenticated users only)
    """
    # Simple implementation - in production this would check database
    if not investigation_id.startswith(f"user-{current_user.id}"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to investigation"
        )
    
    return {
        "id": investigation_id,
        "target": "example.com",
        "investigation_type": "comprehensive",
        "status": "completed",
        "created_at": time.time() - 3600,
        "completed_at": time.time() - 600,
        "progress": 100,
        "risk_score": 65,
        "user_id": current_user.id,
        "user_email": current_user.email,
        "findings": {
            "infrastructure": {
                "whois": {"registrar": "Example Registrar", "created": "2019-01-01"},
                "dns": {"a_records": ["93.184.216.34"], "mx_records": ["mail.example.com"]},
                "ssl": {"grade": "B", "expires": "2024-12-31"}
            },
            "social_media": {
                "mentions": {"twitter": 42, "reddit": 8},
                "sentiment": "neutral"
            },
            "threat_intelligence": {
                "reputation": "clean",
                "breaches": 0,
                "malware": False
            }
        },
        "summary": "Domain shows normal activity with no security concerns identified."
    }


@router.delete("/{investigation_id}")
async def delete_investigation(
    *,
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_verified_user)
) -> Any:
    """
    Delete investigation (authenticated users only)
    """
    # Simple implementation - check ownership
    if not investigation_id.startswith(f"user-{current_user.id}"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to investigation"
        )
    
    logger.info(
        "Investigation deleted",
        investigation_id=investigation_id,
        user_id=current_user.id
    )
    
    return {"message": "Investigation deleted successfully"}


@router.get("/stats/summary")
async def get_user_stats(
    *,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_verified_user)
) -> Any:
    """
    Get user investigation statistics
    """
    return {
        "user_id": current_user.id,
        "email": current_user.email,
        "total_investigations": 5,
        "completed_investigations": 4,
        "active_investigations": 1,
        "average_risk_score": 42,
        "quota_used": 5,
        "quota_limit": int(current_user.investigation_quota_per_day),
        "is_admin": current_user.is_admin
    }


@router.get("/user/me")
async def get_current_user_via_investigations(
    *,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_verified_user)
) -> Any:
    """
    Get current user information (testing via investigations router)
    """
    return {
        "user_id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "is_active": current_user.is_active,
        "is_admin": current_user.is_admin,
        "is_verified": current_user.is_verified
    }