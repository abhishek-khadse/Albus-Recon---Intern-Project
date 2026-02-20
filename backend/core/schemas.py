"""Pydantic schemas for request/response validation."""
from pydantic import BaseModel, EmailStr, validator, Field
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from enum import Enum


# Enums
class UserRole(str, Enum):
    """User role enumeration."""
    ADMIN = "admin"
    ANALYST = "analyst"


class ScanStatus(str, Enum):
    """Scan status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class VulnerabilitySeverity(str, Enum):
    """Vulnerability severity enumeration."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnerabilityStatus(str, Enum):
    """Vulnerability status enumeration."""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# User schemas
class UserBase(BaseModel):
    """Base user schema."""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: Optional[str] = Field(None, max_length=100)
    role: UserRole = UserRole.ANALYST
    is_active: bool = True


class UserCreate(UserBase):
    """User creation schema."""
    password: str = Field(..., min_length=8, max_length=100)
    
    @validator('password')
    def validate_password(cls, v):
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v


class UserUpdate(BaseModel):
    """User update schema."""
    full_name: Optional[str] = Field(None, max_length=100)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None


class UserLogin(BaseModel):
    """User login schema."""
    username: str
    password: str


class UserResponse(UserBase):
    """User response schema."""
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    
    class Config:
        from_attributes = True


# Authentication schemas
class Token(BaseModel):
    """Token response schema."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenRefresh(BaseModel):
    """Token refresh schema."""
    refresh_token: str


# Scan schemas
class ScanBase(BaseModel):
    """Base scan schema."""
    target: str = Field(..., min_length=1, max_length=500)
    scan_type: str = Field(..., min_length=1, max_length=50)
    
    @validator('target')
    def validate_target(cls, v):
        """Validate scan target."""
        if not v.strip():
            raise ValueError('Target cannot be empty')
        return v.strip()


class ScanCreate(ScanBase):
    """Scan creation schema."""
    pass


class ScanResponse(ScanBase):
    """Scan response schema."""
    id: str
    user_id: Optional[int] = None
    status: ScanStatus
    findings: Optional[Dict[str, Any]] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    
    class Config:
        from_attributes = True


# Reconnaissance schemas
class ReconCreate(BaseModel):
    """Reconnaissance creation schema."""
    url: str = Field(..., min_length=1, max_length=500)
    
    @validator('url')
    def validate_url(cls, v):
        """Validate URL format."""
        if not v.strip():
            raise ValueError('URL cannot be empty')
        url = v.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url


class ReconResponse(BaseModel):
    """Reconnaissance response schema."""
    id: int
    url: str
    status_code: int
    title: str
    headers: Optional[Dict[str, str]] = None
    technologies: Optional[Dict[str, Any]] = None
    screenshot_path: Optional[str] = None
    fetched_at: datetime
    scan_id: Optional[str] = None
    owner_id: Optional[int] = None
    
    class Config:
        from_attributes = True


# Vulnerability schemas
class VulnerabilityBase(BaseModel):
    """Base vulnerability schema."""
    target: str = Field(..., min_length=1, max_length=500)
    type: str = Field(..., min_length=1, max_length=100)
    severity: VulnerabilitySeverity = VulnerabilitySeverity.MEDIUM
    title: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1)
    payload: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cve_id: Optional[str] = Field(None, max_length=50)


class VulnerabilityCreate(VulnerabilityBase):
    """Vulnerability creation schema."""
    scan_id: str


class VulnerabilityUpdate(BaseModel):
    """Vulnerability update schema."""
    severity: Optional[VulnerabilitySeverity] = None
    status: Optional[VulnerabilityStatus] = None
    title: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, min_length=1)
    assigned_to: Optional[int] = None
    note: Optional[str] = None


class VulnerabilityResponse(VulnerabilityBase):
    """Vulnerability response schema."""
    id: int
    scan_id: str
    status: VulnerabilityStatus
    created_at: datetime
    updated_at: Optional[datetime] = None
    reported_by: Optional[int] = None
    assigned_to: Optional[int] = None
    
    class Config:
        from_attributes = True


# Tool schemas
class SubdomainRequest(BaseModel):
    """Subdomain enumeration request schema."""
    domain: str = Field(..., min_length=1, max_length=253)
    sources: Optional[List[str]] = ["otx", "crt", "dnsdumpster"]
    
    @validator('domain')
    def validate_domain(cls, v):
        """Validate domain format."""
        if not v.strip():
            raise ValueError('Domain cannot be empty')
        return v.strip().lower()


class SubdomainResponse(BaseModel):
    """Subdomain enumeration response schema."""
    domain: str
    subdomains: List[str]
    count: int
    sources_used: List[str]


class PortScanRequest(BaseModel):
    """Port scan request schema."""
    target: str = Field(..., min_length=1, max_length=253)
    ports: Optional[List[int]] = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1723, 3306, 3389, 5900, 8080, 8443
    ]
    scan_type: str = Field("tcp", max_length=10)
    
    @validator('target')
    def validate_target(cls, v):
        """Validate scan target."""
        if not v.strip():
            raise ValueError('Target cannot be empty')
        return v.strip()
    
    @validator('ports')
    def validate_ports(cls, v):
        """Validate port numbers."""
        for port in v:
            if not (1 <= port <= 65535):
                raise ValueError(f'Port {port} is out of valid range (1-65535)')
        return v


class PortScanResult(BaseModel):
    """Port scan result schema."""
    port: int
    status: str
    service: Optional[str] = None
    banner: Optional[str] = None


class PortScanResponse(BaseModel):
    """Port scan response schema."""
    target: str
    scan_type: str
    results: List[PortScanResult]
    total_ports: int
    open_ports: int
    scan_time: float


# Pagination schemas
class PaginationParams(BaseModel):
    """Pagination parameters schema."""
    page: int = Field(1, ge=1)
    per_page: int = Field(20, ge=1, le=100)
    
    @validator('per_page')
    def validate_per_page(cls, v):
        """Validate per_page limit."""
        return min(v, 100)


class PaginatedResponse(BaseModel):
    """Generic paginated response schema."""
    items: List[Any]
    pagination: Dict[str, Any]
    summary: Optional[Dict[str, Any]] = None


# Error schemas
class ErrorResponse(BaseModel):
    """Error response schema."""
    error: str
    details: Optional[str] = None
    code: Optional[str] = None


# Health check schemas
class HealthCheckResponse(BaseModel):
    """Health check response schema."""
    status: str
    timestamp: datetime
    service: str
    version: str
    database: str
