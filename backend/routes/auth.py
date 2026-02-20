"""Authentication routes."""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer
from typing import Dict, Any

from core.schemas import UserCreate, UserLogin, UserResponse, Token, UserUpdate
from core.auth import get_current_active_user
from services.auth_service import AuthService
from core.logging import get_logger, audit_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/auth", tags=["authentication"])
security = HTTPBearer()
auth_service = AuthService()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    request: Request
) -> UserResponse:
    """Register a new user."""
    try:
        user = auth_service.register_user(user_data)
        
        audit_logger.log_action(
            user_id=user.id,
            action="user_registered",
            resource="user",
            resource_id=str(user.id),
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        return user
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )


@router.post("/login", response_model=Token)
async def login(
    login_data: UserLogin,
    request: Request
) -> Token:
    """Authenticate user and return tokens."""
    try:
        tokens = auth_service.login_user(
            login_data,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        return tokens
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )


@router.post("/refresh", response_model=Token)
async def refresh_token(refresh_token: str) -> Token:
    """Refresh access token."""
    try:
        tokens = auth_service.refresh_token(refresh_token)
        return tokens
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user = Depends(get_current_active_user)
) -> UserResponse:
    """Get current user profile."""
    try:
        return auth_service.get_user_profile(current_user.id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Get profile error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get profile"
        )


@router.put("/me", response_model=UserResponse)
async def update_current_user_profile(
    update_data: UserUpdate,
    current_user = Depends(get_current_active_user),
    request: Request = None
) -> UserResponse:
    """Update current user profile."""
    try:
        user = auth_service.update_user_profile(
            current_user.id,
            update_data.dict(exclude_unset=True)
        )
        
        audit_logger.log_action(
            user_id=current_user.id,
            action="profile_updated",
            resource="user",
            resource_id=str(current_user.id),
            details=update_data.dict(exclude_unset=True),
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None
        )
        
        return user
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Update profile error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update profile"
        )


@router.post("/change-password")
async def change_password(
    current_password: str,
    new_password: str,
    current_user = Depends(get_current_active_user),
    request: Request = None
) -> Dict[str, str]:
    """Change user password."""
    try:
        auth_service.change_password(current_user.id, current_password, new_password)
        
        audit_logger.log_action(
            user_id=current_user.id,
            action="password_changed",
            resource="user",
            resource_id=str(current_user.id),
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None
        )
        
        return {"message": "Password changed successfully"}
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Change password error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to change password"
        )


@router.post("/logout")
async def logout(
    current_user = Depends(get_current_active_user),
    request: Request = None
) -> Dict[str, str]:
    """Logout user."""
    try:
        auth_service.logout_user(current_user.id)
        
        audit_logger.log_action(
            user_id=current_user.id,
            action="user_logged_out",
            resource="user",
            resource_id=str(current_user.id),
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None
        )
        
        return {"message": "Logged out successfully"}
    
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )


@router.get("/validate-token")
async def validate_token(
    credentials = Depends(security)
) -> Dict[str, Any]:
    """Validate JWT token."""
    try:
        token = credentials.credentials
        payload = auth_service.validate_token(token)
        
        if payload:
            return {"valid": True, "payload": payload}
        else:
            return {"valid": False}
    
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        return {"valid": False}
