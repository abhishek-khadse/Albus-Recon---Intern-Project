"""Vulnerability management routes."""
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from typing import List, Optional

from core.schemas import (
    VulnerabilityResponse, VulnerabilityUpdate, PaginationParams,
    VulnerabilitySeverity, VulnerabilityStatus
)
from core.auth import get_current_active_user, require_analyst
from services.vulnerability_service import VulnerabilityService
from core.logging import get_logger, audit_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])
vuln_service = VulnerabilityService()


@router.get("/", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    severity: Optional[VulnerabilitySeverity] = Query(None),
    status: Optional[VulnerabilityStatus] = Query(None),
    vuln_type: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None),
    target: Optional[str] = Query(None),
    current_user = Depends(get_current_active_user)
) -> List[VulnerabilityResponse]:
    """Get vulnerabilities with filtering."""
    try:
        vulns = vuln_service.get_user_vulnerabilities(
            current_user.id, page, per_page, severity, status, vuln_type
        )
        
        # Additional filtering
        if scan_id:
            vulns = [vuln for vuln in vulns if vuln.scan_id == scan_id]
        
        if target:
            vulns = [vuln for vuln in vulns if target.lower() in vuln.target.lower()]
        
        return vulns
    
    except Exception as e:
        logger.error(f"List vulnerabilities error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get vulnerabilities"
        )


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(
    vuln_id: int,
    current_user = Depends(get_current_active_user)
) -> VulnerabilityResponse:
    """Get vulnerability by ID."""
    try:
        vuln = vuln_service.get_vulnerability_by_id(vuln_id, current_user.id)
        
        if not vuln:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vulnerability not found"
            )
        
        return vuln
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get vulnerability error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get vulnerability"
        )


@router.put("/{vuln_id}", response_model=VulnerabilityResponse)
async def update_vulnerability(
    vuln_id: int,
    update_data: VulnerabilityUpdate,
    current_user = Depends(get_current_active_user),
    request: Request = None
) -> VulnerabilityResponse:
    """Update vulnerability."""
    try:
        vuln = vuln_service.update_vulnerability(
            vuln_id, current_user.id, update_data.dict(exclude_unset=True)
        )
        
        if not vuln:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vulnerability not found or access denied"
            )
        
        audit_logger.log_action(
            user_id=current_user.id,
            action="vulnerability_updated",
            resource="vulnerability",
            resource_id=str(vuln_id),
            details=update_data.dict(exclude_unset=True),
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None
        )
        
        return vuln
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update vulnerability error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update vulnerability"
        )


@router.post("/{vuln_id}/assign")
async def assign_vulnerability(
    vuln_id: int,
    assigned_to: int,
    current_user = Depends(get_current_active_user),
    request: Request = None
) -> dict:
    """Assign vulnerability to a user."""
    try:
        success = vuln_service.assign_vulnerability(vuln_id, current_user.id, assigned_to)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vulnerability not found or access denied"
            )
        
        audit_logger.log_action(
            user_id=current_user.id,
            action="vulnerability_assigned",
            resource="vulnerability",
            resource_id=str(vuln_id),
            details={"assigned_to": assigned_to},
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None
        )
        
        return {"message": "Vulnerability assigned successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Assign vulnerability error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to assign vulnerability"
        )


@router.post("/{vuln_id}/status")
async def change_vulnerability_status(
    vuln_id: int,
    status: VulnerabilityStatus,
    current_user = Depends(get_current_active_user),
    request: Request = None
) -> dict:
    """Change vulnerability status."""
    try:
        success = vuln_service.change_vulnerability_status(vuln_id, current_user.id, status)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vulnerability not found or access denied"
            )
        
        audit_logger.log_action(
            user_id=current_user.id,
            action="vulnerability_status_changed",
            resource="vulnerability",
            resource_id=str(vuln_id),
            details={"status": status},
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None
        )
        
        return {"message": "Vulnerability status changed successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Change vulnerability status error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to change vulnerability status"
        )


@router.get("/statistics/summary")
async def get_vulnerability_statistics(
    current_user = Depends(get_current_active_user)
) -> dict:
    """Get vulnerability statistics for current user."""
    try:
        stats = vuln_service.get_vulnerability_statistics(current_user.id)
        return stats
    
    except Exception as e:
        logger.error(f"Get vulnerability statistics error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get vulnerability statistics"
        )


@router.get("/critical/list")
async def get_critical_vulnerabilities(
    current_user = Depends(get_current_active_user)
) -> List[VulnerabilityResponse]:
    """Get critical vulnerabilities."""
    try:
        vulns = vuln_service.get_critical_vulnerabilities(current_user.id)
        return vulns
    
    except Exception as e:
        logger.error(f"Get critical vulnerabilities error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get critical vulnerabilities"
        )


@router.get("/unassigned/list")
async def get_unassigned_vulnerabilities(
    current_user = Depends(get_current_active_user)
) -> List[VulnerabilityResponse]:
    """Get unassigned vulnerabilities."""
    try:
        vulns = vuln_service.get_unassigned_vulnerabilities(current_user.id)
        return vulns
    
    except Exception as e:
        logger.error(f"Get unassigned vulnerabilities error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get unassigned vulnerabilities"
        )


@router.get("/search/{query}")
async def search_vulnerabilities(
    query: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    current_user = Depends(get_current_active_user)
) -> List[VulnerabilityResponse]:
    """Search vulnerabilities."""
    try:
        vulns = vuln_service.search_vulnerabilities(query, current_user.id, page, per_page)
        return vulns
    
    except Exception as e:
        logger.error(f"Search vulnerabilities error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to search vulnerabilities"
        )
