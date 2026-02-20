"""Tools routes for network reconnaissance."""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from typing import List, Optional

from core.schemas import (
    SubdomainRequest, SubdomainResponse, PortScanRequest, PortScanResponse
)
from core.auth import get_current_active_user, require_analyst
from services.tools_service import ToolsService
from core.logging import get_logger, audit_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/tools", tags=["tools"])
tools_service = ToolsService()


@router.post("/subdomains", response_model=SubdomainResponse)
async def find_subdomains(
    request_data: SubdomainRequest,
    current_user = Depends(require_analyst),
    request: Request = None
) -> SubdomainResponse:
    """Find subdomains for a domain."""
    try:
        result = tools_service.find_subdomains(request_data)
        
        audit_logger.log_action(
            user_id=current_user.id,
            action="subdomains_enumerated",
            resource="domain",
            resource_id=request_data.domain,
            details={
                "domain": request_data.domain,
                "sources": request_data.sources,
                "subdomain_count": result.count
            },
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None
        )
        
        return result
    
    except Exception as e:
        logger.error(f"Subdomain enumeration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to enumerate subdomains"
        )


@router.get("/subdomains", response_model=SubdomainResponse)
async def find_subdomains_get(
    domain: str,
    sources: Optional[str] = "otx,crt,dnsdumpster",
    current_user = Depends(require_analyst),
    request: Request = None
) -> SubdomainResponse:
    """Find subdomains for a domain (GET endpoint for compatibility)."""
    try:
        sources_list = [s.strip() for s in sources.split(",") if s.strip()]
        request_data = SubdomainRequest(domain=domain, sources=sources_list)
        
        result = tools_service.find_subdomains(request_data)
        
        audit_logger.log_action(
            user_id=current_user.id,
            action="subdomains_enumerated",
            resource="domain",
            resource_id=domain,
            details={
                "domain": domain,
                "sources": sources_list,
                "subdomain_count": result.count
            },
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None
        )
        
        return result
    
    except Exception as e:
        logger.error(f"Subdomain enumeration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to enumerate subdomains"
        )


@router.post("/port-scan", response_model=PortScanResponse)
async def port_scan(
    request_data: PortScanRequest,
    current_user = Depends(require_analyst),
    request: Request = None
) -> PortScanResponse:
    """Perform port scan on a target."""
    try:
        result = tools_service.port_scan(request_data)
        
        audit_logger.log_action(
            user_id=current_user.id,
            action="port_scan_completed",
            resource="target",
            resource_id=request_data.target,
            details={
                "target": request_data.target,
                "scan_type": request_data.scan_type,
                "port_count": len(request_data.ports),
                "open_ports": result.open_ports,
                "scan_time": result.scan_time
            },
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None
        )
        
        return result
    
    except Exception as e:
        logger.error(f"Port scan error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to perform port scan"
        )


@router.get("/dns-info/{domain}")
async def get_dns_info(
    domain: str,
    current_user = Depends(get_current_active_user)
) -> dict:
    """Get DNS information for a domain."""
    try:
        dns_info = tools_service.get_dns_info(domain)
        return dns_info
    
    except Exception as e:
        logger.error(f"DNS info error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get DNS information"
        )


@router.get("/whois/{domain}")
async def get_whois_info(
    domain: str,
    current_user = Depends(get_current_active_user)
) -> dict:
    """Get WHOIS information for a domain."""
    try:
        import whois
        
        domain_info = whois.whois(domain)
        
        # Convert to serializable format
        result = {}
        for key, value in domain_info.items():
            if isinstance(value, list):
                result[key] = value
            elif hasattr(value, '__dict__'):
                result[key] = str(value)
            else:
                result[key] = value
        
        return result
    
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="WHOIS lookup not available - python-whois not installed"
        )
    except Exception as e:
        logger.error(f"WHOIS lookup error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get WHOIS information"
        )


@router.get("/http-headers/{url:path}")
async def get_http_headers(
    url: str,
    current_user = Depends(get_current_active_user)
) -> dict:
    """Get HTTP headers for a URL."""
    try:
        import requests
        
        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        response = requests.head(url, timeout=10, allow_redirects=True, verify=False)
        
        return {
            "url": url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "final_url": response.url
        }
    
    except Exception as e:
        logger.error(f"HTTP headers error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get HTTP headers"
        )
