"""Authentication and authorization utilities."""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Union
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from config import settings
from core.database import get_db
from core.models import User
from core.schemas import UserRole

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT token handling
security = HTTPBearer()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Generate password hash."""
    return pwd_context.hash(password)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + settings.JWT_ACCESS_TOKEN_EXPIRES
    
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: Dict[str, Any]) -> str:
    """Create JWT refresh token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + settings.JWT_REFRESH_TOKEN_EXPIRES
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def verify_token(token: str, token_type: str = "access") -> Dict[str, Any]:
    """Verify and decode JWT token."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        
        # Check token type
        if payload.get("type") != token_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        # Check expiration
        exp = payload.get("exp")
        if exp is None or datetime.utcnow() > datetime.fromtimestamp(exp):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        
        return payload
    
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """Authenticate user credentials."""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    if not user.is_active:
        return None
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()
    
    return user


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """Get current authenticated user."""
    token = credentials.credentials
    payload = verify_token(token, "access")
    
    user_id: int = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
    
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive"
        )
    
    return user


def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """Get current active user."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user


def require_role(required_role: UserRole):
    """Role-based access control decorator."""
    def role_checker(current_user: User = Depends(get_current_active_user)) -> User:
        if current_user.role != required_role and current_user.role != UserRole.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return current_user
    
    return role_checker


def require_admin(current_user: User = Depends(get_current_active_user)) -> User:
    """Require admin role."""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user


def require_analyst(current_user: User = Depends(get_current_active_user)) -> User:
    """Require analyst role or higher."""
    if current_user.role not in [UserRole.ANALYST, UserRole.ADMIN]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst access required"
        )
    return current_user


class TokenManager:
    """Token management utility class."""
    
    @staticmethod
    def generate_tokens(user: User) -> Dict[str, Any]:
        """Generate access and refresh tokens for user."""
        access_token = create_access_token(data={"sub": str(user.id)})
        refresh_token = create_refresh_token(data={"sub": str(user.id)})
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": int(settings.JWT_ACCESS_TOKEN_EXPIRES.total_seconds())
        }
    
    @staticmethod
    def refresh_access_token(refresh_token: str) -> str:
        """Generate new access token from refresh token."""
        payload = verify_token(refresh_token, "refresh")
        user_id = payload.get("sub")
        
        # Create new access token
        access_token = create_access_token(data={"sub": user_id})
        return access_token


def create_user(db: Session, user_data: Dict[str, Any]) -> User:
    """Create a new user with hashed password."""
    hashed_password = get_password_hash(user_data.pop("password"))
    
    db_user = User(
        **user_data,
        hashed_password=hashed_password
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return db_user


def update_user_password(db: Session, user: User, new_password: str) -> None:
    """Update user password."""
    user.hashed_password = get_password_hash(new_password)
    db.commit()


class PermissionChecker:
    """Permission checking utility."""
    
    @staticmethod
    def can_access_scan(user: User, scan: ScanResult) -> bool:
        """Check if user can access a scan."""
        # Admins can access all scans
        if user.role == UserRole.ADMIN:
            return True
        
        # Users can access their own scans
        if scan.user_id == user.id:
            return True
        
        return False
    
    @staticmethod
    def can_modify_vulnerability(user: User, vulnerability: Vulnerability) -> bool:
        """Check if user can modify a vulnerability."""
        # Admins can modify all vulnerabilities
        if user.role == UserRole.ADMIN:
            return True
        
        # Users can modify vulnerabilities they reported or are assigned to
        if vulnerability.reported_by == user.id or vulnerability.assigned_to == user.id:
            return True
        
        return False
    
    @staticmethod
    def can_assign_vulnerability(user: User, target_user_id: int) -> bool:
        """Check if user can assign vulnerability to target user."""
        # Admins can assign to anyone
        if user.role == UserRole.ADMIN:
            return True
        
        # Users can only assign to themselves
        if target_user_id == user.id:
            return True
        
        return False
