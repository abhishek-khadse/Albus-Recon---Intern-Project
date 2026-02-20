"""Reconnaissance repository for database operations."""
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from core.models import ReconResult, User, ScanResult
from core.schemas import PaginationParams


class ReconRepository:
    """Repository for reconnaissance database operations."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create(self, recon_data: Dict[str, Any]) -> ReconResult:
        """Create a new reconnaissance result."""
        db_recon = ReconResult(**recon_data)
        self.db.add(db_recon)
        self.db.commit()
        self.db.refresh(db_recon)
        
        return db_recon
    
    def get_by_id(self, recon_id: int) -> Optional[ReconResult]:
        """Get reconnaissance result by ID."""
        return self.db.query(ReconResult).filter(ReconResult.id == recon_id).first()
    
    def get_user_recons(
        self,
        user_id: int,
        pagination: PaginationParams,
        status_code: Optional[int] = None,
        scan_id: Optional[str] = None
    ) -> List[ReconResult]:
        """Get reconnaissance results for a specific user."""
        query = self.db.query(ReconResult).filter(ReconResult.owner_id == user_id)
        
        if status_code:
            query = query.filter(ReconResult.status_code == status_code)
        
        if scan_id:
            query = query.filter(ReconResult.scan_id == scan_id)
        
        return query.order_by(ReconResult.fetched_at.desc()).offset(
            (pagination.page - 1) * pagination.per_page
        ).limit(pagination.per_page).all()
    
    def get_scan_recons(self, scan_id: str, pagination: PaginationParams) -> List[ReconResult]:
        """Get reconnaissance results for a specific scan."""
        return self.db.query(ReconResult).filter(
            ReconResult.scan_id == scan_id
        ).order_by(ReconResult.fetched_at.desc()).offset(
            (pagination.page - 1) * pagination.per_page
        ).limit(pagination.per_page).all()
    
    def get_all_recons(
        self,
        pagination: PaginationParams,
        status_code: Optional[int] = None,
        user_id: Optional[int] = None,
        scan_id: Optional[str] = None,
        url_filter: Optional[str] = None
    ) -> List[ReconResult]:
        """Get all reconnaissance results with optional filtering."""
        query = self.db.query(ReconResult)
        
        if status_code:
            query = query.filter(ReconResult.status_code == status_code)
        
        if user_id:
            query = query.filter(ReconResult.owner_id == user_id)
        
        if scan_id:
            query = query.filter(ReconResult.scan_id == scan_id)
        
        if url_filter:
            query = query.filter(ReconResult.url.ilike(f"%{url_filter}%"))
        
        return query.order_by(ReconResult.fetched_at.desc()).offset(
            (pagination.page - 1) * pagination.per_page
        ).limit(pagination.per_page).all()
    
    def update(self, recon_id: int, update_data: Dict[str, Any]) -> Optional[ReconResult]:
        """Update reconnaissance result."""
        db_recon = self.get_by_id(recon_id)
        if not db_recon:
            return None
        
        for field, value in update_data.items():
            if hasattr(db_recon, field):
                setattr(db_recon, field, value)
        
        self.db.commit()
        self.db.refresh(db_recon)
        
        return db_recon
    
    def update_technologies(self, recon_id: int, technologies: Dict[str, Any]) -> Optional[ReconResult]:
        """Update detected technologies."""
        import json
        
        return self.update(recon_id, {"technologies": json.dumps(technologies)})
    
    def update_headers(self, recon_id: int, headers: Dict[str, str]) -> Optional[ReconResult]:
        """Update response headers."""
        import json
        
        return self.update(recon_id, {"headers": json.dumps(headers)})
    
    def get_by_url(self, url: str) -> Optional[ReconResult]:
        """Get reconnaissance result by URL."""
        return self.db.query(ReconResult).filter(ReconResult.url == url).first()
    
    def get_recent_recons(self, limit: int = 10, user_id: Optional[int] = None) -> List[ReconResult]:
        """Get recent reconnaissance results."""
        query = self.db.query(ReconResult)
        
        if user_id:
            query = query.filter(ReconResult.owner_id == user_id)
        
        return query.order_by(ReconResult.fetched_at.desc()).limit(limit).all()
    
    def get_recon_statistics(self, user_id: Optional[int] = None) -> Dict[str, Any]:
        """Get reconnaissance statistics."""
        query = self.db.query(ReconResult)
        
        if user_id:
            query = query.filter(ReconResult.owner_id == user_id)
        
        total_recons = query.count()
        
        # By status code
        status_stats = self.db.query(
            ReconResult.status_code,
            self.db.func.count(ReconResult.id)
        ).filter(
            ReconResult.owner_id == user_id if user_id else True
        ).group_by(ReconResult.status_code).all()
        
        # Successful recon (2xx status codes)
        successful_recons = query.filter(
            ReconResult.status_code >= 200,
            ReconResult.status_code < 300
        ).count()
        
        # Failed recon (4xx, 5xx status codes)
        failed_recons = query.filter(ReconResult.status_code >= 400).count()
        
        return {
            "total_reconnaissance": total_recons,
            "successful_reconnaissance": successful_recons,
            "failed_reconnaissance": failed_recons,
            "success_rate": (successful_recons / total_recons * 100) if total_recons > 0 else 0,
            "by_status_code": dict(status_stats)
        }
    
    def search(self, query: str, pagination: PaginationParams) -> List[ReconResult]:
        """Search reconnaissance results by URL or title."""
        search_filter = or_(
            ReconResult.url.ilike(f"%{query}%"),
            ReconResult.title.ilike(f"%{query}%")
        )
        
        return self.db.query(ReconResult).filter(search_filter).order_by(
            ReconResult.fetched_at.desc()
        ).offset(
            (pagination.page - 1) * pagination.per_page
        ).limit(pagination.per_page).all()
    
    def get_unique_domains(self, user_id: Optional[int] = None) -> List[str]:
        """Get list of unique domains from reconnaissance results."""
        from urllib.parse import urlparse
        
        query = self.db.query(ReconResult.url)
        
        if user_id:
            query = query.filter(ReconResult.owner_id == user_id)
        
        urls = query.all()
        domains = set()
        
        for (url,) in urls:
            try:
                parsed = urlparse(url)
                domains.add(parsed.netloc)
            except Exception:
                continue
        
        return sorted(list(domains))
    
    def count(self, user_id: Optional[int] = None, status_code: Optional[int] = None) -> int:
        """Count reconnaissance results with optional filtering."""
        query = self.db.query(ReconResult)
        
        if user_id:
            query = query.filter(ReconResult.owner_id == user_id)
        
        if status_code:
            query = query.filter(ReconResult.status_code == status_code)
        
        return query.count()
    
    def delete(self, recon_id: int) -> bool:
        """Delete a reconnaissance result."""
        db_recon = self.get_by_id(recon_id)
        if not db_recon:
            return False
        
        self.db.delete(db_recon)
        self.db.commit()
        
        return True
    
    def delete_by_scan_id(self, scan_id: str) -> int:
        """Delete all reconnaissance results for a scan."""
        count = self.db.query(ReconResult).filter(ReconResult.scan_id == scan_id).count()
        self.db.query(ReconResult).filter(ReconResult.scan_id == scan_id).delete()
        self.db.commit()
        
        return count
