"""
Simple investigation endpoints with authentication
"""
from typing import List, Optional, Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
import structlog
import uuid
import time
import json
import redis
import os

from app.core.auth import get_current_verified_user, get_current_active_user
from app.db.session import get_db
from app.models.user import User
from app.services.osint_investigation import OSINTInvestigationService

router = APIRouter()
logger = structlog.get_logger()

# Redis connection for investigation storage
try:
    redis_host = os.getenv("REDIS_HOST", "redis")
    redis_port = int(os.getenv("REDIS_PORT", 6379))
    
    redis_client = redis.Redis(
        host=redis_host,
        port=redis_port,
        decode_responses=True
    )
    
    # Test connection
    result = redis_client.ping()
    logger.info("Redis connection successful for investigation storage", 
                host=redis_host, port=redis_port, ping_result=result)
    redis_client = redis_client
except Exception as e:
    logger.error("Redis connection failed, falling back to in-memory storage", 
                host=os.getenv("REDIS_HOST", "redis"), 
                port=os.getenv("REDIS_PORT", 6379),
                error=str(e))
    redis_client = None

# In-memory storage as fallback
user_investigations = {}


class SimpleInvestigationRequest:
    def __init__(self, target: str, investigation_type: str = "comprehensive"):
        self.target = target
        self.investigation_type = investigation_type


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_investigation(
    *,
    db: AsyncSession = Depends(get_db),
    request_data: Dict[str, Any],
    current_user: User = Depends(get_current_active_user)
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
        
        # For demo purposes, ensure investigations are marked as completed
        if investigation.get("status") != "failed":
            investigation["status"] = "completed"
        
        # Store in user's investigation history
        if redis_client:
            # Use Redis for persistent storage
            user_key = f"investigations:{current_user.id}"
            
            # Get existing investigations
            existing = redis_client.get(user_key)
            if existing:
                investigations_list = json.loads(existing)
            else:
                investigations_list = []
            
            # Add new investigation
            investigations_list.append(investigation)
            
            # Store back to Redis
            redis_client.set(user_key, json.dumps(investigations_list))
            
            logger.info(
                "Investigation stored in Redis",
                user_id=current_user.id,
                investigation_id=investigation["id"],
                target=target,
                risk_score=investigation.get("risk_score", 0),
                user_investigations_count=len(investigations_list)
            )
        else:
            # Fallback to in-memory
            if current_user.id not in user_investigations:
                user_investigations[current_user.id] = []
            user_investigations[current_user.id].append(investigation)
            
            logger.info(
                "Investigation stored in memory",
                user_id=current_user.id,
                investigation_id=investigation["id"],
                target=target,
                risk_score=investigation.get("risk_score", 0),
                total_users_in_storage=len(user_investigations),
                user_investigations_count=len(user_investigations[current_user.id])
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
    current_user: User = Depends(get_current_active_user)
) -> Any:
    """
    List user's investigations (authenticated users only)
    """
    # Get user's actual investigations
    if redis_client:
        # Load from Redis
        user_key = f"investigations:{current_user.id}"
        stored_data = redis_client.get(user_key)
        
        if stored_data:
            user_invs = json.loads(stored_data)
            logger.info(
                "Loaded investigations from Redis",
                user_id=current_user.id,
                user_investigations_count=len(user_invs)
            )
        else:
            user_invs = []
            logger.info(
                "No investigations found in Redis",
                user_id=current_user.id
            )
    else:
        # Fallback to in-memory
        user_invs = user_investigations.get(current_user.id, [])
        logger.info(
            "Loading from memory",
            user_id=current_user.id,
            total_users_in_storage=len(user_investigations),
            user_investigations_count=len(user_invs),
            all_user_keys=list(user_investigations.keys())
        )
    
    # Sort by creation time (newest first)
    sorted_investigations = sorted(
        user_invs, 
        key=lambda x: x.get("created_at", 0), 
        reverse=True
    )
    
    return {
        "investigations": sorted_investigations,
        "total": len(sorted_investigations),
        "page": 1,
        "per_page": 20,
        "user_email": current_user.email
    }


@router.get("/{investigation_id}")
async def get_investigation(
    *,
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Any:
    """
    Get specific investigation details (authenticated users only)
    """
    # Get user's investigations
    if redis_client:
        # Load from Redis
        user_key = f"investigations:{current_user.id}"
        stored_data = redis_client.get(user_key)
        
        if stored_data:
            user_invs = json.loads(stored_data)
        else:
            user_invs = []
    else:
        # Fallback to in-memory
        user_invs = user_investigations.get(current_user.id, [])
    
    # Find the specific investigation
    investigation = None
    for inv in user_invs:
        if inv.get("id") == investigation_id:
            investigation = inv
            break
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    # Verify ownership (additional security check)
    if investigation.get("user_id") != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to investigation"
        )
    
    return investigation


@router.delete("/{investigation_id}")
async def delete_investigation(
    *,
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Any:
    """
    Delete investigation (authenticated users only)
    """
    # Get user's investigations
    if redis_client:
        # Load from Redis
        user_key = f"investigations:{current_user.id}"
        stored_data = redis_client.get(user_key)
        
        if stored_data:
            user_invs = json.loads(stored_data)
        else:
            user_invs = []
    else:
        # Fallback to in-memory
        user_invs = user_investigations.get(current_user.id, [])
    
    # Find and remove the investigation
    investigation_found = False
    for i, inv in enumerate(user_invs):
        if inv.get("id") == investigation_id:
            # Verify ownership
            if inv.get("user_id") != current_user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied to investigation"
                )
            
            # Remove the investigation
            user_invs.pop(i)
            investigation_found = True
            
            # Save back to storage
            if redis_client:
                # Update Redis
                user_key = f"investigations:{current_user.id}"
                redis_client.set(user_key, json.dumps(user_invs))
            else:
                # Update in-memory
                user_investigations[current_user.id] = user_invs
            
            break
    
    if not investigation_found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
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
    current_user: User = Depends(get_current_active_user)
) -> Any:
    """
    Get user investigation statistics
    """
    # Get user's investigations
    if redis_client:
        # Load from Redis
        user_key = f"investigations:{current_user.id}"
        stored_data = redis_client.get(user_key)
        
        if stored_data:
            user_invs = json.loads(stored_data)
        else:
            user_invs = []
    else:
        # Fallback to in-memory
        user_invs = user_investigations.get(current_user.id, [])
    
    total_investigations = len(user_invs)
    completed_investigations = len([inv for inv in user_invs if inv.get("status") == "completed"])
    active_investigations = len([inv for inv in user_invs if inv.get("status") in ["processing", "in_progress"]])
    
    # Calculate average risk score for completed investigations
    risk_scores = [inv.get("risk_score", 0) for inv in user_invs if inv.get("risk_score") is not None]
    average_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0
    
    return {
        "user_id": current_user.id,
        "email": current_user.email,
        "total_investigations": total_investigations,
        "completed_investigations": completed_investigations,
        "active_investigations": active_investigations,
        "average_risk_score": round(average_risk_score, 1),
        "quota_used": total_investigations,
        "quota_limit": int(current_user.investigation_quota_per_day),
        "is_admin": current_user.is_admin
    }


@router.get("/user/me")
async def get_current_user_via_investigations(
    *,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
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


@router.get("/debug/status")
async def debug_investigations_status(
    *,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Any:
    """
    Debug endpoint to check investigation statuses
    """
    # Get user's investigations
    if redis_client:
        # Load from Redis
        user_key = f"investigations:{current_user.id}"
        stored_data = redis_client.get(user_key)
        
        if stored_data:
            user_invs = json.loads(stored_data)
        else:
            user_invs = []
            
        logger.info("Debug: Redis investigations", 
                   user_id=current_user.id,
                   count=len(user_invs),
                   investigations=[{
                       "id": inv.get("id"),
                       "target": inv.get("target"),
                       "status": inv.get("status")
                   } for inv in user_invs])
    else:
        # Fallback to in-memory
        user_invs = user_investigations.get(current_user.id, [])
        
        logger.info("Debug: In-memory investigations",
                   user_id=current_user.id,
                   count=len(user_invs),
                   investigations=[{
                       "id": inv.get("id"),
                       "target": inv.get("target"), 
                       "status": inv.get("status")
                   } for inv in user_invs])
    
    return {
        "user_id": current_user.id,
        "storage_type": "redis" if redis_client else "in_memory",
        "investigation_count": len(user_invs),
        "investigations": [{
            "id": inv.get("id"),
            "target": inv.get("target"),
            "status": inv.get("status"),
            "created_at": inv.get("created_at"),
            "risk_score": inv.get("risk_score")
        } for inv in user_invs]
    }


@router.get("/{investigation_id}/report")
async def generate_investigation_report(
    *,
    investigation_id: str,
    format: str = "pdf",  # pdf, html, or txt
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Any:
    """
    Generate professional report for investigation (PDF, HTML, or text format)
    """
    from app.services.report_generator import report_generator
    
    # Get investigation details
    if redis_client:
        # Load from Redis
        user_key = f"investigations:{current_user.id}"
        stored_data = redis_client.get(user_key)
        
        if stored_data:
            user_invs = json.loads(stored_data)
        else:
            user_invs = []
    else:
        # Fallback to in-memory
        user_invs = user_investigations.get(current_user.id, [])
    
    # Find the specific investigation
    investigation = None
    for inv in user_invs:
        if inv.get("id") == investigation_id:
            investigation = inv
            break
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    # Verify ownership
    if investigation.get("user_id") != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to investigation"
        )
    
    logger.info(
        "Generating investigation report",
        investigation_id=investigation_id,
        format=format,
        user_id=current_user.id,
        target=investigation.get("target")
    )
    
    # Generate professional report using the report service
    return await report_generator.generate_investigation_report(
        investigation=investigation,
        user_email=current_user.email,
        format=format
    )