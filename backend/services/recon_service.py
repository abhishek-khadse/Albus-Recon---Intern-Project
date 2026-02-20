"""Reconnaissance service for URL scanning and analysis."""
import requests
import socket
import json
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse, urlunparse
from datetime import datetime
from bs4 import BeautifulSoup

from core.database import DatabaseManager
from core.models import ReconResult, User
from core.schemas import ReconCreate, ReconResponse, ScanStatus
from core.logging import get_logger, security_logger

logger = get_logger(__name__)


class ReconService:
    """Service for reconnaissance operations."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'DNT': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
        })
    
    def create_recon(self, recon_data: ReconCreate, user_id: Optional[int] = None) -> ReconResponse:
        """Create a new reconnaissance scan."""
        url = self._normalize_url(recon_data.url)
        
        # Perform reconnaissance
        start_time = datetime.utcnow()
        
        try:
            response_data = self._fetch_url(url)
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            # Extract additional information
            title = self._extract_title(response_data.get('content', ''))
            technologies = self._detect_technologies(response_data.get('headers', {}), response_data.get('content', ''))
            
            # Save to database
            recon_record = {
                'url': url,
                'status_code': response_data['status_code'],
                'title': title,
                'headers': json.dumps(response_data.get('headers', {})),
                'technologies': json.dumps(technologies),
                'owner_id': user_id
            }
            
            with DatabaseManager() as db:
                from repositories.recon_repository import ReconRepository
                recon_repo = ReconRepository(db)
                
                recon = recon_repo.create(recon_record)
                
                logger.info(f"Reconnaissance completed for {url} in {duration:.2f}s")
                
                return ReconResponse(
                    id=recon.id,
                    url=recon.url,
                    status_code=recon.status_code,
                    title=recon.title,
                    headers=recon.headers_dict,
                    technologies=recon.technologies_dict,
                    screenshot_path=recon.screenshot_path,
                    fetched_at=recon.fetched_at,
                    scan_id=recon.scan_id,
                    owner_id=recon.owner_id
                )
        
        except Exception as e:
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.error(f"Reconnaissance failed for {url}: {e}")
            
            # Save failed attempt
            recon_record = {
                'url': url,
                'status_code': 0,
                'title': f"[Error: {str(e)}]",
                'owner_id': user_id
            }
            
            with DatabaseManager() as db:
                from repositories.recon_repository import ReconRepository
                recon_repo = ReconRepository(db)
                
                recon = recon_repo.create(recon_record)
                
                return ReconResponse(
                    id=recon.id,
                    url=recon.url,
                    status_code=recon.status_code,
                    title=recon.title,
                    fetched_at=recon.fetched_at,
                    owner_id=recon.owner_id
                )
    
    def get_recon_by_id(self, recon_id: int, user_id: Optional[int] = None) -> Optional[ReconResponse]:
        """Get reconnaissance result by ID."""
        with DatabaseManager() as db:
            from repositories.recon_repository import ReconRepository
            recon_repo = ReconRepository(db)
            
            recon = recon_repo.get_by_id(recon_id)
            if not recon:
                return None
            
            # Check permissions if user_id is provided
            if user_id and recon.owner_id != user_id:
                from core.auth import PermissionChecker
                if not PermissionChecker.can_access_scan(None, recon):  # Need to pass user object
                    return None
            
            return ReconResponse(
                id=recon.id,
                url=recon.url,
                status_code=recon.status_code,
                title=recon.title,
                headers=recon.headers_dict,
                technologies=recon.technologies_dict,
                screenshot_path=recon.screenshot_path,
                fetched_at=recon.fetched_at,
                scan_id=recon.scan_id,
                owner_id=recon.owner_id
            )
    
    def get_user_recons(self, user_id: int, page: int = 1, per_page: int = 20) -> List[ReconResponse]:
        """Get reconnaissance results for a user."""
        from core.schemas import PaginationParams
        
        pagination = PaginationParams(page=page, per_page=per_page)
        
        with DatabaseManager() as db:
            from repositories.recon_repository import ReconRepository
            recon_repo = ReconRepository(db)
            
            recons = recon_repo.get_user_recons(user_id, pagination)
            
            return [
                ReconResponse(
                    id=recon.id,
                    url=recon.url,
                    status_code=recon.status_code,
                    title=recon.title,
                    headers=recon.headers_dict,
                    technologies=recon.technologies_dict,
                    screenshot_path=recon.screenshot_path,
                    fetched_at=recon.fetched_at,
                    scan_id=recon.scan_id,
                    owner_id=recon.owner_id
                ) for recon in recons
            ]
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL by adding protocol if missing."""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url
    
    def _fetch_url(self, url: str, timeout: int = 15) -> Dict[str, Any]:
        """Fetch URL and return response data."""
        try:
            response = self.session.get(url, timeout=timeout, verify=False, allow_redirects=True)
            
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text,
                'url': response.url,
                'history': [resp.url for resp in response.history]
            }
        
        except requests.exceptions.SSLError:
            # Retry without SSL verification
            try:
                response = self.session.get(url, timeout=timeout, verify=False, allow_redirects=True)
                return {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'content': response.text,
                    'url': response.url,
                    'history': [resp.url for resp in response.history]
                }
            except Exception as e:
                raise Exception(f"SSL error and retry failed: {e}")
        
        except requests.exceptions.Timeout:
            raise Exception(f"Request timed out after {timeout} seconds")
        
        except requests.exceptions.TooManyRedirects:
            raise Exception("Too many redirects")
        
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request failed: {e}")
    
    def _extract_title(self, html_content: str) -> str:
        """Extract title from HTML content."""
        try:
            if not html_content:
                return "No content"
            
            soup = BeautifulSoup(html_content, 'html.parser')
            title_tag = soup.find('title')
            
            if title_tag:
                title = title_tag.get_text().strip()
                return title if title else "No title found"
            
            # Check for JavaScript applications
            js_indicators = ['react', 'vue', 'angular', 'next.js', 'nuxt.js']
            if any(indicator in html_content.lower() for indicator in js_indicators):
                return "[JavaScript Application - Content requires JavaScript to be enabled]"
            
            return "No title found"
        
        except Exception as e:
            logger.error(f"Error extracting title: {e}")
            return f"[Error parsing content: {str(e)}]"
    
    def _detect_technologies(self, headers: Dict[str, str], content: str) -> Dict[str, Any]:
        """Detect web technologies from headers and content."""
        technologies = {}
        
        # Server information
        server = headers.get('Server', '').lower()
        if server:
            if 'apache' in server:
                technologies['web_server'] = 'Apache'
            elif 'nginx' in server:
                technologies['web_server'] = 'Nginx'
            elif 'iis' in server:
                technologies['web_server'] = 'IIS'
            else:
                technologies['web_server'] = server
        
        # PHP detection
        if 'x-powered-by' in headers and 'php' in headers['x-powered-by'].lower():
            technologies['backend'] = 'PHP'
        
        # ASP.NET detection
        if 'x-aspnet-version' in headers or 'x-powered-by' in headers and 'asp.net' in headers['x-powered-by'].lower():
            technologies['backend'] = 'ASP.NET'
        
        # Python frameworks detection
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by'].lower()
            if 'django' in powered_by:
                technologies['backend'] = 'Django'
            elif 'flask' in powered_by:
                technologies['backend'] = 'Flask'
            elif 'fastapi' in powered_by:
                technologies['backend'] = 'FastAPI'
        
        # Content analysis
        if content:
            content_lower = content.lower()
            
            # JavaScript frameworks
            if 'react' in content_lower:
                technologies['frontend'] = 'React'
            elif 'vue' in content_lower:
                technologies['frontend'] = 'Vue.js'
            elif 'angular' in content_lower:
                technologies['Angular'] in content_lower
            elif 'jquery' in content_lower:
                technologies['jQuery'] = 'jQuery'
            
            # CMS detection
            if 'wp-content' in content_lower or 'wordpress' in content_lower:
                technologies['cms'] = 'WordPress'
            elif 'drupal' in content_lower:
                technologies['cms'] = 'Drupal'
            elif 'joomla' in content_lower:
                technologies['cms'] = 'Joomla'
            
            # Analytics
            if 'google-analytics' in content_lower or 'ga(' in content_lower:
                technologies['analytics'] = 'Google Analytics'
            elif 'hotjar' in content_lower:
                technologies['analytics'] = 'Hotjar'
        
        return technologies
    
    def get_recon_statistics(self, user_id: Optional[int] = None) -> Dict[str, Any]:
        """Get reconnaissance statistics."""
        with DatabaseManager() as db:
            from repositories.recon_repository import ReconRepository
            recon_repo = ReconRepository(db)
            
            return recon_repo.get_recon_statistics(user_id)
    
    def search_recons(self, query: str, user_id: Optional[int] = None, page: int = 1, per_page: int = 20) -> List[ReconResponse]:
        """Search reconnaissance results."""
        from core.schemas import PaginationParams
        
        pagination = PaginationParams(page=page, per_page=per_page)
        
        with DatabaseManager() as db:
            from repositories.recon_repository import ReconRepository
            recon_repo = ReconRepository(db)
            
            recons = recon_repo.search(query, pagination)
            
            # Filter by user if specified
            if user_id:
                recons = [recon for recon in recons if recon.owner_id == user_id]
            
            return [
                ReconResponse(
                    id=recon.id,
                    url=recon.url,
                    status_code=recon.status_code,
                    title=recon.title,
                    headers=recon.headers_dict,
                    technologies=recon.technologies_dict,
                    screenshot_path=recon.screenshot_path,
                    fetched_at=recon.fetched_at,
                    scan_id=recon.scan_id,
                    owner_id=recon.owner_id
                ) for recon in recons
            ]
    
    def delete_recon(self, recon_id: int, user_id: int) -> bool:
        """Delete reconnaissance result."""
        with DatabaseManager() as db:
            from repositories.recon_repository import ReconRepository
            recon_repo = ReconRepository(db)
            
            recon = recon_repo.get_by_id(recon_id)
            if not recon:
                return False
            
            # Check permissions
            if recon.owner_id != user_id:
                from core.auth import PermissionChecker
                # Need to implement proper permission checking
                return False
            
            return recon_repo.delete(recon_id)
