"""Authentication service for user management and security."""
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

from core.database import DatabaseManager
from core.models import User
from core.schemas import UserCreate, UserLogin, UserResponse, Token, UserRole
from core.auth import (
    authenticate_user, create_user, update_user_password, TokenManager,
    verify_password, get_password_hash
)
from core.logging import get_logger, security_logger

logger = get_logger(__name__)


class AuthService:
    """Service for authentication and user management operations."""
    
    def __init__(self):
        self.token_manager = TokenManager()
    
    def register_user(self, user_data: UserCreate) -> UserResponse:
        """Register a new user."""
        with DatabaseManager() as db:
            from repositories.user_repository import UserRepository
            user_repo = UserRepository(db)
            
            # Check if username already exists
            if user_repo.exists_by_username(user_data.username):
                raise ValueError("Username already exists")
            
            # Check if email already exists
            if user_repo.exists_by_email(user_data.email):
                raise ValueError("Email already exists")
            
            # Create user
            user = create_user(db, user_data.dict())
            
            security_logger.log_login(user.username, True)
            
            return UserResponse.from_orm(user)
    
    def login_user(self, login_data: UserLogin, ip_address: str = None, user_agent: str = None) -> Token:
        """Authenticate user and return tokens."""
        with DatabaseManager() as db:
            user = authenticate_user(db, login_data.username, login_data.password)
            
            if not user:
                security_logger.log_login(login_data.username, False, ip_address, user_agent)
                raise ValueError("Invalid username or password")
            
            # Generate tokens
            tokens = self.token_manager.generate_tokens(user)
            
            security_logger.log_login(user.username, True, ip_address, user_agent)
            
            return Token(**tokens)
    
    def refresh_token(self, refresh_token: str) -> Token:
        """Refresh access token using refresh token."""
        try:
            access_token = self.token_manager.refresh_access_token(refresh_token)
            
            return Token(
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="bearer",
                expires_in=3600  # 1 hour
            )
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            raise ValueError("Invalid refresh token")
    
    def change_password(self, user_id: int, current_password: str, new_password: str) -> bool:
        """Change user password."""
        with DatabaseManager() as db:
            from repositories.user_repository import UserRepository
            user_repo = UserRepository(db)
            
            user = user_repo.get_by_id(user_id)
            if not user:
                raise ValueError("User not found")
            
            # Verify current password
            if not verify_password(current_password, user.hashed_password):
                raise ValueError("Current password is incorrect")
            
            # Update password
            update_user_password(db, user, new_password)
            
            logger.info(f"Password changed for user {user.username}")
            return True
    
    def reset_password(self, user_id: int, new_password: str) -> bool:
        """Reset user password (admin only)."""
        with DatabaseManager() as db:
            from repositories.user_repository import UserRepository
            user_repo = UserRepository(db)
            
            user = user_repo.get_by_id(user_id)
            if not user:
                raise ValueError("User not found")
            
            # Update password
            update_user_password(db, user, new_password)
            
            logger.info(f"Password reset for user {user.username}")
            return True
    
    def get_user_profile(self, user_id: int) -> UserResponse:
        """Get user profile information."""
        with DatabaseManager() as db:
            from repositories.user_repository import UserRepository
            user_repo = UserRepository(db)
            
            user = user_repo.get_by_id(user_id)
            if not user:
                raise ValueError("User not found")
            
            return UserResponse.from_orm(user)
    
    def update_user_profile(self, user_id: int, update_data: Dict[str, Any]) -> UserResponse:
        """Update user profile information."""
        with DatabaseManager() as db:
            from repositories.user_repository import UserRepository
            user_repo = UserRepository(db)
            
            user = user_repo.get_by_id(user_id)
            if not user:
                raise ValueError("User not found")
            
            # Check if updating username/email and if they already exist
            if 'username' in update_data:
                existing_user = user_repo.get_by_username(update_data['username'])
                if existing_user and existing_user.id != user_id:
                    raise ValueError("Username already exists")
            
            if 'email' in update_data:
                existing_user = user_repo.get_by_email(update_data['email'])
                if existing_user and existing_user.id != user_id:
                    raise ValueError("Email already exists")
            
            # Update user
            from core.schemas import UserUpdate
            user_update = UserUpdate(**update_data)
            updated_user = user_repo.update(user_id, user_update)
            
            logger.info(f"Profile updated for user {user.username}")
            return UserResponse.from_orm(updated_user)
    
    def deactivate_user(self, user_id: int) -> bool:
        """Deactivate user account."""
        with DatabaseManager() as db:
            from repositories.user_repository import UserRepository
            user_repo = UserRepository(db)
            
            user = user_repo.get_by_id(user_id)
            if not user:
                raise ValueError("User not found")
            
            user_repo.deactivate(user_id)
            
            logger.info(f"User {user.username} deactivated")
            return True
    
    def activate_user(self, user_id: int) -> bool:
        """Activate user account."""
        with DatabaseManager() as db:
            from repositories.user_repository import UserRepository
            user_repo = UserRepository(db)
            
            user = user_repo.get_by_id(user_id)
            if not user:
                raise ValueError("User not found")
            
            user_repo.activate(user_id)
            
            logger.info(f"User {user.username} activated")
            return True
    
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate JWT token and return payload."""
        try:
            from core.auth import verify_token
            return verify_token(token, "access")
        except Exception as e:
            logger.error(f"Token validation failed: {e}")
            return None
    
    def is_token_expired(self, token: str) -> bool:
        """Check if token is expired."""
        try:
            from core.auth import verify_token
            verify_token(token, "access")
            return False
        except Exception:
            return True
    
    def get_user_from_token(self, token: str) -> Optional[UserResponse]:
        """Get user from JWT token."""
        payload = self.validate_token(token)
        if not payload:
            return None
        
        user_id = payload.get("sub")
        if not user_id:
            return None
        
        try:
            return self.get_user_profile(int(user_id))
        except Exception:
            return None
    
    def create_admin_user(self, username: str, email: str, password: str) -> UserResponse:
        """Create admin user (for initial setup)."""
        admin_data = UserCreate(
            username=username,
            email=email,
            password=password,
            role=UserRole.ADMIN,
            full_name="System Administrator"
        )
        
        return self.register_user(admin_data)
    
    def validate_password_strength(self, password: str) -> bool:
        """Validate password strength requirements."""
        if len(password) < 8:
            return False
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        return has_upper and has_lower and has_digit and has_special
    
    def logout_user(self, user_id: int) -> bool:
        """Logout user (log the event)."""
        with DatabaseManager() as db:
            from repositories.user_repository import UserRepository
            user_repo = UserRepository(db)
            
            user = user_repo.get_by_id(user_id)
            if not user:
                raise ValueError("User not found")
            
            security_logger.log_logout(user_id, user.username)
            return True
