"""Scan repository for database operations."""
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from core.models import ScanResult, User, Vulnerability, ReconResult
from core.schemas import ScanStatus, PaginationParams


class ScanRepository:
    """Repository for scan database operations."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create(self, scan_data: Dict[str, Any]) -> ScanResult:
        """Create a new scan."""
        db_scan = ScanResult(**scan_data)
        self.db.add(db_scan)
        self.db.commit()
        self.db.refresh(db_scan)
        
        return db_scan
    
    def get_by_id(self, scan_id: str) -> Optional[ScanResult]:
        """Get scan by ID."""
        return self.db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    
    def get_user_scans(
        self,
        user_id: int,
        pagination: PaginationParams,
        status: Optional[ScanStatus] = None,
        scan_type: Optional[str] = None
    ) -> List[ScanResult]:
        """Get scans for a specific user."""
        query = self.db.query(ScanResult).filter(ScanResult.user_id == user_id)
        
        if status:
            query = query.filter(ScanResult.status == status)
        
        if scan_type:
            query = query.filter(ScanResult.scan_type == scan_type)
        
        return query.order_by(ScanResult.started_at.desc()).offset(
            (pagination.page - 1) * pagination.per_page
        ).limit(pagination.per_page).all()
    
    def get_all_scans(
        self,
        pagination: PaginationParams,
        status: Optional[ScanStatus] = None,
        scan_type: Optional[str] = None,
        user_id: Optional[int] = None
    ) -> List[ScanResult]:
        """Get all scans with optional filtering."""
        query = self.db.query(ScanResult)
        
        if status:
            query = query.filter(ScanResult.status == status)
        
        if scan_type:
            query = query.filter(ScanResult.scan_type == scan_type)
        
        if user_id:
            query = query.filter(ScanResult.user_id == user_id)
        
        return query.order_by(ScanResult.started_at.desc()).offset(
            (pagination.page - 1) * pagination.per_page
        ).limit(pagination.per_page).all()
    
    def update_status(self, scan_id: str, status: ScanStatus, error: Optional[str] = None) -> Optional[ScanResult]:
        """Update scan status."""
        db_scan = self.get_by_id(scan_id)
        if not db_scan:
            return None
        
        db_scan.status = status
        if error:
            db_scan.error = error
        
        if status == ScanStatus.COMPLETED:
            from datetime import datetime
            db_scan.completed_at = datetime.utcnow()
        
        self.db.commit()
        self.db.refresh(db_scan)
        
        return db_scan
    
    def update_findings(self, scan_id: str, findings: Dict[str, Any]) -> Optional[ScanResult]:
        """Update scan findings."""
        import json
        
        db_scan = self.get_by_id(scan_id)
        if not db_scan:
            return None
        
        db_scan.findings = json.dumps(findings)
        self.db.commit()
        self.db.refresh(db_scan)
        
        return db_scan
    
    def get_running_scans(self) -> List[ScanResult]:
        """Get all currently running scans."""
        return self.db.query(ScanResult).filter(
            ScanResult.status == ScanStatus.RUNNING
        ).all()
    
    def get_scan_statistics(self, user_id: Optional[int] = None) -> Dict[str, Any]:
        """Get scan statistics."""
        query = self.db.query(ScanResult)
        
        if user_id:
            query = query.filter(ScanResult.user_id == user_id)
        
        total_scans = query.count()
        completed_scans = query.filter(ScanResult.status == ScanStatus.COMPLETED).count()
        failed_scans = query.filter(ScanResult.status == ScanStatus.FAILED).count()
        running_scans = query.filter(ScanResult.status == ScanStatus.RUNNING).count()
        pending_scans = query.filter(ScanResult.status == ScanStatus.PENDING).count()
        
        # Scan type distribution
        scan_types = self.db.query(
            ScanResult.scan_type,
            self.db.func.count(ScanResult.id)
        ).filter(ScanResult.user_id == user_id if user_id else True).group_by(
            ScanResult.scan_type
        ).all()
        
        return {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "failed_scans": failed_scans,
            "running_scans": running_scans,
            "pending_scans": pending_scans,
            "success_rate": (completed_scans / total_scans * 100) if total_scans > 0 else 0,
            "scan_types": dict(scan_types)
        }
    
    def delete(self, scan_id: str) -> bool:
        """Delete a scan and its related data."""
        db_scan = self.get_by_id(scan_id)
        if not db_scan:
            return False
        
        # Delete related vulnerabilities and recon results
        self.db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).delete()
        self.db.query(ReconResult).filter(ReconResult.scan_id == scan_id).delete()
        
        # Delete the scan
        self.db.delete(db_scan)
        self.db.commit()
        
        return True
    
    def count(self, user_id: Optional[int] = None, status: Optional[ScanStatus] = None) -> int:
        """Count scans with optional filtering."""
        query = self.db.query(ScanResult)
        
        if user_id:
            query = query.filter(ScanResult.user_id == user_id)
        
        if status:
            query = query.filter(ScanResult.status == status)
        
        return query.count()
    
    def get_recent_scans(self, limit: int = 10, user_id: Optional[int] = None) -> List[ScanResult]:
        """Get recent scans."""
        query = self.db.query(ScanResult)
        
        if user_id:
            query = query.filter(ScanResult.user_id == user_id)
        
        return query.order_by(ScanResult.started_at.desc()).limit(limit).all()
