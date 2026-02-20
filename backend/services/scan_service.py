"""Scan service for vulnerability scanning and analysis."""
import asyncio
import uuid
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

from core.database import DatabaseManager
from core.models import ScanResult, User, Vulnerability
from core.schemas import ScanCreate, ScanResponse, ScanStatus, VulnerabilityCreate
from core.logging import get_logger, security_logger

# Import security modules
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from security.vulnerability_scanner import VulnerabilityScanner
from security.dns_analyzer import DNSAnalyzer
from security.api_key_detector import APIKeyDetector

logger = get_logger(__name__)


class ScanService:
    """Service for vulnerability scanning operations."""
    
    def __init__(self):
        self.running_scans = {}  # Track running scans in memory
    
    def create_scan(self, scan_data: ScanCreate, user_id: Optional[int] = None) -> ScanResponse:
        """Create and start a new scan."""
        scan_id = str(uuid.uuid4())
        
        # Create scan record
        scan_record = {
            'id': scan_id,
            'user_id': user_id,
            'target': scan_data.target,
            'scan_type': scan_data.scan_type,
            'status': ScanStatus.PENDING
        }
        
        with DatabaseManager() as db:
            from repositories.scan_repository import ScanRepository
            scan_repo = ScanRepository(db)
            
            scan = scan_repo.create(scan_record)
            
            # Start scan in background
            self._start_scan_async(scan_id, scan_data.target, scan_data.scan_type, user_id)
            
            security_logger.log_scan_started(user_id, scan_id, scan_data.target, scan_data.scan_type)
            
            return ScanResponse.from_orm(scan)
    
    def get_scan_by_id(self, scan_id: str, user_id: Optional[int] = None) -> Optional[ScanResponse]:
        """Get scan result by ID."""
        with DatabaseManager() as db:
            from repositories.scan_repository import ScanRepository
            scan_repo = ScanRepository(db)
            
            scan = scan_repo.get_by_id(scan_id)
            if not scan:
                return None
            
            # Check permissions
            if user_id and scan.user_id != user_id:
                from core.auth import PermissionChecker
                # Need to implement proper permission checking
                return None
            
            # Parse findings if present
            findings = None
            if scan.findings:
                try:
                    import json
                    findings = json.loads(scan.findings)
                except json.JSONDecodeError:
                    findings = {}
            
            return ScanResponse(
                id=scan.id,
                user_id=scan.user_id,
                target=scan.target,
                scan_type=scan.scan_type,
                status=scan.status,
                findings=findings,
                started_at=scan.started_at,
                completed_at=scan.completed_at,
                error=scan.error
            )
    
    def get_user_scans(self, user_id: int, page: int = 1, per_page: int = 20) -> List[ScanResponse]:
        """Get scans for a user."""
        from core.schemas import PaginationParams
        
        pagination = PaginationParams(page=page, per_page=per_page)
        
        with DatabaseManager() as db:
            from repositories.scan_repository import ScanRepository
            scan_repo = ScanRepository(db)
            
            scans = scan_repo.get_user_scans(user_id, pagination)
            
            return [
                ScanResponse(
                    id=scan.id,
                    user_id=scan.user_id,
                    target=scan.target,
                    scan_type=scan.scan_type,
                    status=scan.status,
                    findings=scan.findings,
                    started_at=scan.started_at,
                    completed_at=scan.completed_at,
                    error=scan.error
                ) for scan in scans
            ]
    
    def _start_scan_async(self, scan_id: str, target: str, scan_type: str, user_id: Optional[int] = None):
        """Start scan in background."""
        try:
            # Mark scan as running
            with DatabaseManager() as db:
                from repositories.scan_repository import ScanRepository
                scan_repo = ScanRepository(db)
                scan_repo.update_status(scan_id, ScanStatus.RUNNING)
            
            # Run the actual scan
            if scan_type == 'full':
                self._run_full_scan(scan_id, target, user_id)
            elif scan_type == 'xss':
                self._run_xss_scan(scan_id, target, user_id)
            elif scan_type == 'dns':
                self._run_dns_scan(scan_id, target, user_id)
            elif scan_type == 'api_keys':
                self._run_api_key_scan(scan_id, target, user_id)
            else:
                self._run_generic_scan(scan_id, target, scan_type, user_id)
        
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            with DatabaseManager() as db:
                from repositories.scan_repository import ScanRepository
                scan_repo = ScanRepository(db)
                scan_repo.update_status(scan_id, ScanStatus.FAILED, str(e))
    
    def _run_full_scan(self, scan_id: str, target: str, user_id: Optional[int] = None):
        """Run comprehensive vulnerability scan."""
        start_time = datetime.utcnow()
        
        try:
            # Initialize vulnerability scanner
            scanner = VulnerabilityScanner(target)
            
            # Run all scan types
            scan_types = ['xss', 'dns', 'api_keys', 'ssl', 'headers']
            results = scanner.run_scan(scan_types)
            
            # Save findings
            with DatabaseManager() as db:
                from repositories.scan_repository import ScanRepository
                scan_repo = ScanRepository(db)
                scan_repo.update_findings(scan_id, results)
                scan_repo.update_status(scan_id, ScanStatus.COMPLETED)
                
                # Create vulnerability records
                self._create_vulnerability_records(db, scan_id, target, results, user_id)
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            security_logger.log_scan_completed(scan_id, "completed", duration)
            
        except Exception as e:
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.error(f"Full scan {scan_id} failed: {e}")
            
            with DatabaseManager() as db:
                from repositories.scan_repository import ScanRepository
                scan_repo = ScanRepository(db)
                scan_repo.update_status(scan_id, ScanStatus.FAILED, str(e))
            
            security_logger.log_scan_completed(scan_id, "failed", duration)
    
    def _run_xss_scan(self, scan_id: str, target: str, user_id: Optional[int] = None):
        """Run XSS vulnerability scan."""
        start_time = datetime.utcnow()
        
        try:
            scanner = VulnerabilityScanner(target)
            results = scanner.run_scan(['xss'])
            
            with DatabaseManager() as db:
                from repositories.scan_repository import ScanRepository
                scan_repo = ScanRepository(db)
                scan_repo.update_findings(scan_id, results)
                scan_repo.update_status(scan_id, ScanStatus.COMPLETED)
                
                self._create_vulnerability_records(db, scan_id, target, results, user_id)
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            security_logger.log_scan_completed(scan_id, "completed", duration)
            
        except Exception as e:
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.error(f"XSS scan {scan_id} failed: {e}")
            
            with DatabaseManager() as db:
                from repositories.scan_repository import ScanRepository
                scan_repo = ScanRepository(db)
                scan_repo.update_status(scan_id, ScanStatus.FAILED, str(e))
            
            security_logger.log_scan_completed(scan_id, "failed", duration)
    
    def _run_dns_scan(self, scan_id: str, target: str, user_id: Optional[int] = None):
        """Run DNS analysis scan."""
        start_time = datetime.utcnow()
        
        try:
            analyzer = DNSAnalyzer(target)
            results = analyzer.analyze_dns()
            
            with DatabaseManager() as db:
                from repositories.scan_repository import ScanRepository
                scan_repo = ScanRepository(db)
                scan_repo.update_findings(scan_id, results)
                scan_repo.update_status(scan_id, ScanStatus.COMPLETED)
                
                self._create_vulnerability_records(db, scan_id, target, results, user_id)
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            security_logger.log_scan_completed(scan_id, "completed", duration)
            
        except Exception as e:
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.error(f"DNS scan {scan_id} failed: {e}")
            
            with DatabaseManager() as db:
                from repositories.scan_repository import ScanRepository
                scan_repo = ScanRepository(db)
                scan_repo.update_status(scan_id, ScanStatus.FAILED, str(e))
            
            security_logger.log_scan_completed(scan_id, "failed", duration)
    
    def _run_api_key_scan(self, scan_id: str, target: str, user_id: Optional[int] = None):
        """Run API key detection scan."""
        start_time = datetime.utcnow()
        
        try:
            detector = APIKeyDetector(target)
            results = detector.scan_for_api_keys()
            
            with DatabaseManager() as db:
                from repositories.scan_repository import ScanRepository
                scan_repo = ScanRepository(db)
                scan_repo.update_findings(scan_id, results)
                scan_repo.update_status(scan_id, ScanStatus.COMPLETED)
                
                self._create_vulnerability_records(db, scan_id, target, results, user_id)
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            security_logger.log_scan_completed(scan_id, "completed", duration)
            
        except Exception as e:
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.error(f"API key scan {scan_id} failed: {e}")
            
            with DatabaseManager() as db:
                from repositories.scan_repository import ScanRepository
                scan_repo = ScanRepository(db)
                scan_repo.update_status(scan_id, ScanStatus.FAILED, str(e))
            
            security_logger.log_scan_completed(scan_id, "failed", duration)
    
    def _run_generic_scan(self, scan_id: str, target: str, scan_type: str, user_id: Optional[int] = None):
        """Run generic scan type."""
        start_time = datetime.utcnow()
        
        try:
            scanner = VulnerabilityScanner(target)
            results = scanner.run_scan([scan_type])
            
            with DatabaseManager() as db:
                from repositories.scan_repository import ScanRepository
                scan_repo = ScanRepository(db)
                scan_repo.update_findings(scan_id, results)
                scan_repo.update_status(scan_id, ScanStatus.COMPLETED)
                
                self._create_vulnerability_records(db, scan_id, target, results, user_id)
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            security_logger.log_scan_completed(scan_id, "completed", duration)
            
        except Exception as e:
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.error(f"Generic scan {scan_id} failed: {e}")
            
            with DatabaseManager() as db:
                from repositories.scan_repository import ScanRepository
                scan_repo = ScanRepository(db)
                scan_repo.update_status(scan_id, ScanStatus.FAILED, str(e))
            
            security_logger.log_scan_completed(scan_id, "failed", duration)
    
    def _create_vulnerability_records(self, db, scan_id: str, target: str, results: Dict[str, Any], user_id: Optional[int] = None):
        """Create vulnerability records from scan results."""
        from repositories.vulnerability_repository import VulnerabilityRepository
        from core.schemas import VulnerabilitySeverity
        
        vuln_repo = VulnerabilityRepository(db)
        
        # Process scan results and create vulnerabilities
        scan_results = results.get('scan_results', {})
        
        for scan_type, scan_data in scan_results.items():
            if isinstance(scan_data, dict) and 'vulnerabilities' in scan_data:
                for vuln_data in scan_data['vulnerabilities']:
                    vuln_record = {
                        'scan_id': scan_id,
                        'target': target,
                        'type': vuln_data.get('type', scan_type),
                        'severity': vuln_data.get('severity', VulnerabilitySeverity.MEDIUM),
                        'title': vuln_data.get('title', f'{scan_type.title()} Vulnerability'),
                        'description': vuln_data.get('description', ''),
                        'payload': vuln_data.get('payload'),
                        'request': vuln_data.get('request'),
                        'response': vuln_data.get('response'),
                        'cvss_score': vuln_data.get('cvss_score'),
                        'cve_id': vuln_data.get('cve_id'),
                        'reported_by': user_id
                    }
                    
                    vulnerability = vuln_repo.create(vuln_record)
                    security_logger.log_vulnerability_created(user_id, vulnerability.id, target)
    
    def get_scan_statistics(self, user_id: Optional[int] = None) -> Dict[str, Any]:
        """Get scan statistics."""
        with DatabaseManager() as db:
            from repositories.scan_repository import ScanRepository
            scan_repo = ScanRepository(db)
            
            return scan_repo.get_scan_statistics(user_id)
    
    def cancel_scan(self, scan_id: str, user_id: int) -> bool:
        """Cancel a running scan."""
        with DatabaseManager() as db:
            from repositories.scan_repository import ScanRepository
            scan_repo = ScanRepository(db)
            
            scan = scan_repo.get_by_id(scan_id)
            if not scan:
                return False
            
            # Check permissions
            if scan.user_id != user_id:
                return False
            
            if scan.status == ScanStatus.RUNNING:
                scan_repo.update_status(scan_id, ScanStatus.FAILED, "Cancelled by user")
                return True
            
            return False
    
    def delete_scan(self, scan_id: str, user_id: int) -> bool:
        """Delete a scan and its related data."""
        with DatabaseManager() as db:
            from repositories.scan_repository import ScanRepository
            scan_repo = ScanRepository(db)
            
            scan = scan_repo.get_by_id(scan_id)
            if not scan:
                return False
            
            # Check permissions
            if scan.user_id != user_id:
                return False
            
            return scan_repo.delete(scan_id)
