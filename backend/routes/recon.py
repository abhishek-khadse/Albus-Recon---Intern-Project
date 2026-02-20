"""Reconnaissance routes."""
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from typing import List, Optional

from core.schemas import (
    ReconCreate, ReconResponse, PaginationParams, PaginatedResponse
)
from core.auth import get_current_active_user, require_analyst
from services.recon_service import ReconService
from core.logging import get_logger, audit_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/recon", tags=["reconnaissance"])
recon_service = ReconService()


@router.post("/", response_model=ReconResponse, status_code=status.HTTP_201_CREATED)
async def create_recon(
    recon_data: ReconCreate,
    current_user = Depends(require_analyst),
    request: Request = None
) -> ReconResponse:
    """Create a new reconnaissance scan."""
    try:
        recon = recon_service.create_recon(recon_data, current_user.id)
        
        audit_logger.log_action(
            user_id=current_user.id,
            action="recon_created",
            resource="recon",
            resource_id=str(recon.id),
            details={"url": recon_data.url},
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None
        )
        
        return recon
    
    except Exception as e:
        logger.error(f"Create recon error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create reconnaissance"
        )


@router.get("/", response_model=List[ReconResponse])
async def list_user_recons(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    current_user = Depends(get_current_active_user)
) -> List[ReconResponse]:
    """Get reconnaissance results for current user."""
    try:
        recons = recon_service.get_user_recons(current_user.id, page, per_page)
        return recons
    
    except Exception as e:
        logger.error(f"List recons error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get reconnaissance results"
        )


@router.get("/{recon_id}", response_model=ReconResponse)
async def get_recon(
    recon_id: int,
    current_user = Depends(get_current_active_user)
) -> ReconResponse:
    """Get reconnaissance result by ID."""
    try:
        recon = recon_service.get_recon_by_id(recon_id, current_user.id)
        
        if not recon:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Reconnaissance result not found"
            )
        
        return recon
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get recon error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get reconnaissance result"
        )


@router.delete("/{recon_id}")
async def delete_recon(
    recon_id: int,
    current_user = Depends(get_current_active_user),
    request: Request = None
) -> dict:
    """Delete reconnaissance result."""
    try:
        success = recon_service.delete_recon(recon_id, current_user.id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Reconnaissance result not found or access denied"
            )
        
        audit_logger.log_action(
            user_id=current_user.id,
            action="recon_deleted",
            resource="recon",
            resource_id=str(recon_id),
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None
        )
        
        return {"message": "Reconnaissance result deleted successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete recon error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete reconnaissance result"
        )


@router.get("/search/{query}", response_model=List[ReconResponse])
async def search_recons(
    query: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    current_user = Depends(get_current_active_user)
) -> List[ReconResponse]:
    """Search reconnaissance results."""
    try:
        recons = recon_service.search_recons(query, current_user.id, page, per_page)
        return recons
    
    except Exception as e:
        logger.error(f"Search recons error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to search reconnaissance results"
        )


@router.get("/statistics/summary")
async def get_recon_statistics(
    current_user = Depends(get_current_active_user)
) -> dict:
    """Get reconnaissance statistics for current user."""
    try:
        stats = recon_service.get_recon_statistics(current_user.id)
        return stats
    
    except Exception as e:
        logger.error(f"Get recon statistics error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get reconnaissance statistics"
        )
