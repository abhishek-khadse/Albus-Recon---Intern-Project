"""Database models for Albus Recon."""
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, Float, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
import uuid
import json

from core.database import Base


class User(Base):
    """User model for authentication and authorization."""
    
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    role = Column(String(20), default="analyst")  # admin, analyst
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    scans = relationship("ScanResult", back_populates="user")
    vulnerabilities_reported = relationship("Vulnerability", foreign_keys="Vulnerability.reported_by", back_populates="reporter")
    vulnerabilities_assigned = relationship("Vulnerability", foreign_keys="Vulnerability.assigned_to", back_populates="assignee")


class ScanResult(Base):
    """Scan results model for tracking reconnaissance and vulnerability scans."""
    
    __tablename__ = "scan_results"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=True)
    target = Column(String(500), nullable=False)
    scan_type = Column(String(50), nullable=False)  # full, xss, dns, port, etc.
    status = Column(String(20), default="pending")  # pending, running, completed, failed
    findings = Column(Text)  # JSON string of scan results
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error = Column(Text, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan")
    recon_results = relationship("ReconResult", back_populates="scan")


class ReconResult(Base):
    """Reconnaissance results model for URL scanning."""
    
    __tablename__ = "recon_results"
    
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(500), index=True, nullable=False)
    status_code = Column(Integer, nullable=False)
    title = Column(String(500), default="")
    headers = Column(Text, nullable=True)  # JSON string of response headers
    technologies = Column(Text, nullable=True)  # JSON string of detected technologies
    screenshot_path = Column(String(500), nullable=True)
    fetched_at = Column(DateTime(timezone=True), server_default=func.now())
    scan_id = Column(String(36), ForeignKey("scan_results.id"), index=True, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=True)
    
    # Relationships
    scan = relationship("ScanResult", back_populates="recon_results")
    owner = relationship("User")
    
    @property
    def headers_dict(self) -> dict:
        """Get headers as dictionary."""
        try:
            return json.loads(self.headers) if self.headers else {}
        except json.JSONDecodeError:
            return {}
    
    @property
    def technologies_dict(self) -> dict:
        """Get technologies as dictionary."""
        try:
            return json.loads(self.technologies) if self.technologies else {}
        except json.JSONDecodeError:
            return {}


class Vulnerability(Base):
    """Vulnerability model for security findings."""
    
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(36), ForeignKey("scan_results.id"), index=True, nullable=False)
    target = Column(String(500), nullable=False)
    type = Column(String(100), nullable=False)  # xss, sqli, misconfiguration, etc.
    severity = Column(String(20), default="medium")  # low, medium, high, critical
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    payload = Column(Text, nullable=True)
    request = Column(Text, nullable=True)
    response = Column(Text, nullable=True)
    cvss_score = Column(Float, nullable=True)
    cve_id = Column(String(50), nullable=True)
    status = Column(String(20), default="open")  # open, in_progress, resolved, false_positive
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    reported_by = Column(Integer, ForeignKey("users.id"), index=True, nullable=True)
    assigned_to = Column(Integer, ForeignKey("users.id"), index=True, nullable=True)
    
    # Relationships
    scan = relationship("ScanResult", back_populates="vulnerabilities")
    reporter = relationship("User", foreign_keys=[reported_by], back_populates="vulnerabilities_reported")
    assignee = relationship("User", foreign_keys=[assigned_to], back_populates="vulnerabilities_assigned")


class ApiKey(Base):
    """API key model for external service authentication."""
    
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    key_hash = Column(String(255), nullable=False, unique=True)
    service = Column(String(50), nullable=False)  # shodan, dnsdumpster, etc.
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used = Column(DateTime(timezone=True), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Relationships
    creator = relationship("User")


class AuditLog(Base):
    """Audit log model for tracking user actions."""
    
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=True)
    action = Column(String(100), nullable=False)
    resource = Column(String(100), nullable=False)
    resource_id = Column(String(100), nullable=True)
    details = Column(Text, nullable=True)  # JSON string of additional details
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    user = relationship("User")
