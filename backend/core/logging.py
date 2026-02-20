"""Centralized logging configuration."""
import logging
import sys
import json
from datetime import datetime
from typing import Any, Dict
from pathlib import Path

from config import settings


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in {
                'name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                'filename', 'module', 'lineno', 'funcName', 'created',
                'msecs', 'relativeCreated', 'thread', 'threadName',
                'processName', 'process', 'getMessage', 'exc_info',
                'exc_text', 'stack_info'
            }:
                log_entry[key] = value
        
        return json.dumps(log_entry)


class SecurityLogger:
    """Security-specific logger for authentication and authorization events."""
    
    def __init__(self):
        self.logger = logging.getLogger("security")
    
    def log_login(self, username: str, success: bool, ip_address: str = None, user_agent: str = None):
        """Log login attempt."""
        self.logger.info(
            f"Login attempt for user: {username}",
            extra={
                "event_type": "login",
                "username": username,
                "success": success,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
    
    def log_logout(self, user_id: int, username: str):
        """Log logout event."""
        self.logger.info(
            f"User logged out: {username}",
            extra={
                "event_type": "logout",
                "user_id": user_id,
                "username": username,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
    
    def log_permission_denied(self, user_id: int, resource: str, action: str):
        """Log permission denied event."""
        self.logger.warning(
            f"Permission denied for user {user_id} on {resource}",
            extra={
                "event_type": "permission_denied",
                "user_id": user_id,
                "resource": resource,
                "action": action,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
    
    def log_vulnerability_created(self, user_id: int, vuln_id: int, target: str):
        """Log vulnerability creation."""
        self.logger.info(
            f"Vulnerability created: {vuln_id} for target: {target}",
            extra={
                "event_type": "vulnerability_created",
                "user_id": user_id,
                "vulnerability_id": vuln_id,
                "target": target,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
    
    def log_scan_started(self, user_id: int, scan_id: str, target: str, scan_type: str):
        """Log scan start."""
        self.logger.info(
            f"Scan started: {scan_id} for target: {target}",
            extra={
                "event_type": "scan_started",
                "user_id": user_id,
                "scan_id": scan_id,
                "target": target,
                "scan_type": scan_type,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
    
    def log_scan_completed(self, scan_id: str, status: str, duration: float):
        """Log scan completion."""
        self.logger.info(
            f"Scan completed: {scan_id} with status: {status}",
            extra={
                "event_type": "scan_completed",
                "scan_id": scan_id,
                "status": status,
                "duration": duration,
                "timestamp": datetime.utcnow().isoformat()
            }
        )


class AuditLogger:
    """Audit logger for tracking user actions."""
    
    def __init__(self):
        self.logger = logging.getLogger("audit")
    
    def log_action(
        self,
        user_id: int,
        action: str,
        resource: str,
        resource_id: str = None,
        details: Dict[str, Any] = None,
        ip_address: str = None,
        user_agent: str = None
    ):
        """Log user action for audit trail."""
        self.logger.info(
            f"User action: {action} on {resource}",
            extra={
                "event_type": "user_action",
                "user_id": user_id,
                "action": action,
                "resource": resource,
                "resource_id": resource_id,
                "details": details or {},
                "ip_address": ip_address,
                "user_agent": user_agent,
                "timestamp": datetime.utcnow().isoformat()
            }
        )


def setup_logging():
    """Setup application logging configuration."""
    # Create logs directory if it doesn't exist
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper()))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    
    # File handler for application logs
    app_handler = logging.FileHandler(log_dir / "app.log")
    app_handler.setLevel(logging.INFO)
    
    # File handler for security logs
    security_handler = logging.FileHandler(log_dir / "security.log")
    security_handler.setLevel(logging.INFO)
    
    # File handler for audit logs
    audit_handler = logging.FileHandler(log_dir / "audit.log")
    audit_handler.setLevel(logging.INFO)
    
    # File handler for error logs
    error_handler = logging.FileHandler(log_dir / "error.log")
    error_handler.setLevel(logging.ERROR)
    
    # Set formatters
    if settings.LOG_FORMAT.lower() == "json":
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    console_handler.setFormatter(formatter)
    app_handler.setFormatter(formatter)
    security_handler.setFormatter(formatter)
    audit_handler.setFormatter(formatter)
    error_handler.setFormatter(formatter)
    
    # Add handlers to root logger
    root_logger.addHandler(console_handler)
    root_logger.addHandler(app_handler)
    root_logger.addHandler(error_handler)
    
    # Configure specific loggers
    security_logger = logging.getLogger("security")
    security_logger.addHandler(security_handler)
    security_logger.propagate = False
    
    audit_logger = logging.getLogger("audit")
    audit_logger.addHandler(audit_handler)
    audit_logger.propagate = False
    
    # Configure third-party loggers
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
    logging.getLogger("requests.packages.urllib3").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get logger instance with specified name."""
    return logging.getLogger(name)


# Global logger instances
security_logger = SecurityLogger()
audit_logger = AuditLogger()


def log_request_response(
    method: str,
    url: str,
    status_code: int,
    duration: float,
    user_id: int = None,
    ip_address: str = None
):
    """Log HTTP request and response."""
    logger = get_logger("http")
    
    logger.info(
        f"{method} {url} - {status_code}",
        extra={
            "event_type": "http_request",
            "method": method,
            "url": url,
            "status_code": status_code,
            "duration": duration,
            "user_id": user_id,
            "ip_address": ip_address,
            "timestamp": datetime.utcnow().isoformat()
        }
    )


def log_error(
    error: Exception,
    context: str = None,
    user_id: int = None,
    additional_data: Dict[str, Any] = None
):
    """Log error with context."""
    logger = get_logger("error")
    
    logger.error(
        f"Error in {context}: {str(error)}",
        extra={
            "event_type": "error",
            "context": context,
            "error_type": type(error).__name__,
            "error_message": str(error),
            "user_id": user_id,
            "additional_data": additional_data or {},
            "timestamp": datetime.utcnow().isoformat()
        },
        exc_info=True
    )
