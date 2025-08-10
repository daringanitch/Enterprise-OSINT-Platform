"""
Investigation endpoints with async support
"""
from typing import List, Optional, Any
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.db.session import get_db
from app.core.auth import get_current_user
from app.schemas.investigation import (
    InvestigationCreate,
    InvestigationUpdate,
    InvestigationResponse,
    InvestigationListResponse,
    BulkInvestigationCreate,
    InvestigationExport,
    InvestigationSummary
)
from app.models.user import User
from app.services.investigation_service import InvestigationService
from app.tasks.osint_tasks import investigate_target
from app.utils.pagination import paginate
from app.utils.rate_limit import rate_limit

router = APIRouter()
logger = structlog.get_logger()


@router.post("/", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
@rate_limit("10/hour")
async def create_investigation(
    *,
    db: AsyncSession = Depends(get_db),
    investigation_in: InvestigationCreate,
    current_user: User = Depends(get_current_user),
    background_tasks: BackgroundTasks
) -> Any:
    """
    Create a new investigation and start processing
    """
    service = InvestigationService(db)
    
    # Check user's investigation quota
    if not await service.check_user_quota(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Investigation quota exceeded. Please wait for current investigations to complete."
        )
    
    # Create investigation
    investigation = await service.create_investigation(
        user_id=current_user.id,
        **investigation_in.dict()
    )
    
    # Start async investigation task
    task = investigate_target.delay(
        investigation_id=str(investigation.id),
        target=investigation.target,
        investigation_type=investigation.investigation_type
    )
    
    # Update investigation with task ID
    investigation = await service.update_investigation(
        investigation_id=investigation.id,
        task_id=task.id
    )
    
    logger.info(
        "Investigation created",
        investigation_id=str(investigation.id),
        user_id=str(current_user.id),
        target=investigation.target
    )
    
    return investigation


@router.post("/bulk", response_model=List[InvestigationResponse])
@rate_limit("5/hour")
async def create_bulk_investigations(
    *,
    db: AsyncSession = Depends(get_db),
    bulk_in: BulkInvestigationCreate,
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Create multiple investigations at once
    """
    service = InvestigationService(db)
    
    # Check if user can create this many investigations
    if not await service.check_user_quota(current_user.id, count=len(bulk_in.targets)):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Cannot create {len(bulk_in.targets)} investigations. Quota exceeded."
        )
    
    investigations = []
    
    for target in bulk_in.targets:
        investigation = await service.create_investigation(
            user_id=current_user.id,
            target=target,
            investigation_type=bulk_in.investigation_type,
            tags=bulk_in.common_tags,
            priority=bulk_in.priority
        )
        
        # Start async task
        task = investigate_target.delay(
            investigation_id=str(investigation.id),
            target=target,
            investigation_type=bulk_in.investigation_type
        )
        
        investigation = await service.update_investigation(
            investigation_id=investigation.id,
            task_id=task.id
        )
        
        investigations.append(investigation)
    
    logger.info(
        "Bulk investigations created",
        count=len(investigations),
        user_id=str(current_user.id)
    )
    
    return investigations


@router.get("/", response_model=InvestigationListResponse)
async def list_investigations(
    *,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    target: Optional[str] = None,
    type: Optional[str] = None,
    sort_by: str = Query("created_at", regex="^(created_at|updated_at|priority|risk_score)$"),
    order: str = Query("desc", regex="^(asc|desc)$")
) -> Any:
    """
    List user's investigations with filtering and pagination
    """
    service = InvestigationService(db)
    
    # Build filters
    filters = {"user_id": current_user.id}
    if status:
        filters["status"] = status
    if target:
        filters["target"] = target
    if type:
        filters["investigation_type"] = type
    
    # Get paginated results
    investigations = await service.list_investigations(
        filters=filters,
        page=page,
        per_page=per_page,
        sort_by=sort_by,
        order=order
    )
    
    return investigations


@router.get("/{investigation_id}", response_model=InvestigationResponse)
async def get_investigation(
    *,
    db: AsyncSession = Depends(get_db),
    investigation_id: str,
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Get investigation details
    """
    service = InvestigationService(db)
    
    investigation = await service.get_investigation(investigation_id)
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    # Check ownership
    if investigation.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this investigation"
        )
    
    # Get real-time progress from Celery
    if investigation.task_id:
        progress = await service.get_investigation_progress(investigation.task_id)
        investigation.progress = progress.get("percent", 0)
        investigation.estimated_completion = progress.get("eta")
    
    return investigation


@router.patch("/{investigation_id}", response_model=InvestigationResponse)
async def update_investigation(
    *,
    db: AsyncSession = Depends(get_db),
    investigation_id: str,
    investigation_in: InvestigationUpdate,
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Update investigation metadata
    """
    service = InvestigationService(db)
    
    investigation = await service.get_investigation(investigation_id)
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    # Check ownership
    if investigation.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this investigation"
        )
    
    # Update investigation
    investigation = await service.update_investigation(
        investigation_id=investigation_id,
        **investigation_in.dict(exclude_unset=True)
    )
    
    return investigation


@router.delete("/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_investigation(
    *,
    db: AsyncSession = Depends(get_db),
    investigation_id: str,
    current_user: User = Depends(get_current_user)
) -> None:
    """
    Delete an investigation
    """
    service = InvestigationService(db)
    
    investigation = await service.get_investigation(investigation_id)
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    # Check ownership
    if investigation.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this investigation"
        )
    
    # Cancel task if running
    if investigation.task_id and investigation.status in ["pending", "processing"]:
        await service.cancel_investigation(investigation.task_id)
    
    # Delete investigation
    await service.delete_investigation(investigation_id)
    
    logger.info(
        "Investigation deleted",
        investigation_id=investigation_id,
        user_id=str(current_user.id)
    )


@router.post("/{investigation_id}/cancel", response_model=InvestigationResponse)
async def cancel_investigation(
    *,
    db: AsyncSession = Depends(get_db),
    investigation_id: str,
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Cancel a running investigation
    """
    service = InvestigationService(db)
    
    investigation = await service.get_investigation(investigation_id)
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    # Check ownership
    if investigation.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to cancel this investigation"
        )
    
    # Cancel if running
    if investigation.status not in ["pending", "processing"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Investigation is not running"
        )
    
    # Cancel task
    if investigation.task_id:
        await service.cancel_investigation(investigation.task_id)
    
    # Update status
    investigation = await service.update_investigation(
        investigation_id=investigation_id,
        status="cancelled"
    )
    
    return investigation


@router.get("/{investigation_id}/summary", response_model=InvestigationSummary)
async def get_investigation_summary(
    *,
    db: AsyncSession = Depends(get_db),
    investigation_id: str,
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Get investigation summary with key findings
    """
    service = InvestigationService(db)
    
    investigation = await service.get_investigation(investigation_id)
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    # Check ownership
    if investigation.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this investigation"
        )
    
    # Get summary
    summary = await service.get_investigation_summary(investigation_id)
    
    return summary


@router.post("/{investigation_id}/export")
async def export_investigation(
    *,
    db: AsyncSession = Depends(get_db),
    investigation_id: str,
    export_params: InvestigationExport,
    current_user: User = Depends(get_current_user)
) -> StreamingResponse:
    """
    Export investigation data in various formats
    """
    service = InvestigationService(db)
    
    investigation = await service.get_investigation(investigation_id)
    
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found"
        )
    
    # Check ownership
    if investigation.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to export this investigation"
        )
    
    # Generate export
    export_data = await service.export_investigation(
        investigation_id=investigation_id,
        format=export_params.format,
        options=export_params.dict()
    )
    
    # Return appropriate response based on format
    if export_params.format == "json":
        return StreamingResponse(
            export_data,
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename=investigation_{investigation_id}.json"
            }
        )
    elif export_params.format == "pdf":
        return StreamingResponse(
            export_data,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=investigation_{investigation_id}.pdf"
            }
        )
    # Add other formats as needed