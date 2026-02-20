"""Scan routes."""
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from typing import List, Optional

from core.schemas import (
    ScanCreate, ScanResponse, PaginationParams, ScanStatus
)
from core.auth import get_current_active_user, require_analyst
from services.scan_service import ScanService
from core.logging import get_logger, audit_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/scans", tags=["scans"])
scan_service = ScanService()


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_data: ScanCreate,
    current_user = Depends(require_analyst),
    request: Request = None
) -> ScanResponse:
    """Create and start a new scan."""
    try:
        scan = scan_service.create_scan(scan_data, current_user.id)
        
        audit_logger.log_action(
            user_id=current_user.id,
            action="scan_created",
            resource="scan",
            resource_id=scan.id,
            details={
                "target": scan_data.target,
                "scan_type": scan_data.scan_type
            },
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None
        )
        
        return scan
    
    except Exception as e:
        logger.error(f"Create scan error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create scan"
        )


@router.get("/", response_model=List[ScanResponse])
async def list_user_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: Optional[ScanStatus] = Query(None),
    scan_type: Optional[str] = Query(None),
    current_user = Depends(get_current_active_user)
) -> List[ScanResponse]:
    """Get scans for current user."""
    try:
        scans = scan_service.get_user_scans(current_user.id, page, per_page)
        
        # Filter by status and type if specified
        if status:
            scans = [scan for scan in scans if scan.status == status]
        
        if scan_type:
            scans = [scan for scan in scans if scan.scan_type == scan_type]
        
        return scans
    
    except Exception as e:
        logger.error(f"List scans error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get scans"
        )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    current_user = Depends(get_current_active_user)
) -> ScanResponse:
    """Get scan result by ID."""
    try:
        scan = scan_service.get_scan_by_id(scan_id, current_user.id)
        
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found"
            )
        
        return scan
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get scan error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get scan result"
        )


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    current_user = Depends(get_current_active_user),
    request: Request = None
) -> dict:
    """Cancel a running scan."""
    try:
        success = scan_service.cancel_scan(scan_id, current_user.id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found, access denied, or scan cannot be cancelled"
            )
        
        audit_logger.log_action(
            user_id=current_user.id,
            action="scan_cancelled",
            resource="scan",
            resource_id=scan_id,
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None
        )
        
        return {"message": "Scan cancelled successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Cancel scan error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cancel scan"
        )


@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: str,
    current_user = Depends(get_current_active_user),
    request: Request = None
) -> dict:
    """Delete a scan and its related data."""
    try:
        success = scan_service.delete_scan(scan_id, current_user.id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found or access denied"
            )
        
        audit_logger.log_action(
            user_id=current_user.id,
            action="scan_deleted",
            resource="scan",
            resource_id=scan_id,
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None
        )
        
        return {"message": "Scan deleted successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete scan error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete scan"
        )


@router.get("/statistics/summary")
async def get_scan_statistics(
    current_user = Depends(get_current_active_user)
) -> dict:
    """Get scan statistics for current user."""
    try:
        stats = scan_service.get_scan_statistics(current_user.id)
        return stats
    
    except Exception as e:
        logger.error(f"Get scan statistics error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get scan statistics"
        )


@router.get("/running/list")
async def get_running_scans(
    current_user = Depends(get_current_active_user)
) -> List[ScanResponse]:
    """Get currently running scans for user."""
    try:
        all_scans = scan_service.get_user_scans(current_user.id, 1, 100)
        running_scans = [scan for scan in all_scans if scan.status == ScanStatus.RUNNING]
        return running_scans
    
    except Exception as e:
        logger.error(f"Get running scans error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get running scans"
        )
