"""User repository for database operations."""
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import or_

from core.models import User
from core.schemas import UserCreate, UserUpdate, UserRole
from core.auth import get_password_hash


class UserRepository:
    """Repository for user database operations."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create(self, user_data: UserCreate) -> User:
        """Create a new user."""
        hashed_password = get_password_hash(user_data.password)
        
        db_user = User(
            username=user_data.username,
            email=user_data.email,
            full_name=user_data.full_name,
            role=user_data.role,
            is_active=user_data.is_active,
            hashed_password=hashed_password
        )
        
        self.db.add(db_user)
        self.db.commit()
        self.db.refresh(db_user)
        
        return db_user
    
    def get_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID."""
        return self.db.query(User).filter(User.id == user_id).first()
    
    def get_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        return self.db.query(User).filter(User.username == username).first()
    
    def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        return self.db.query(User).filter(User.email == email).first()
    
    def get_by_username_or_email(self, identifier: str) -> Optional[User]:
        """Get user by username or email."""
        return self.db.query(User).filter(
            or_(User.username == identifier, User.email == identifier)
        ).first()
    
    def get_all(
        self,
        skip: int = 0,
        limit: int = 100,
        role: Optional[UserRole] = None,
        is_active: Optional[bool] = None
    ) -> List[User]:
        """Get all users with optional filtering."""
        query = self.db.query(User)
        
        if role:
            query = query.filter(User.role == role)
        
        if is_active is not None:
            query = query.filter(User.is_active == is_active)
        
        return query.offset(skip).limit(limit).all()
    
    def update(self, user_id: int, user_data: UserUpdate) -> Optional[User]:
        """Update user information."""
        db_user = self.get_by_id(user_id)
        if not db_user:
            return None
        
        update_data = user_data.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(db_user, field, value)
        
        self.db.commit()
        self.db.refresh(db_user)
        
        return db_user
    
    def update_password(self, user_id: int, new_password: str) -> Optional[User]:
        """Update user password."""
        db_user = self.get_by_id(user_id)
        if not db_user:
            return None
        
        db_user.hashed_password = get_password_hash(new_password)
        self.db.commit()
        self.db.refresh(db_user)
        
        return db_user
    
    def deactivate(self, user_id: int) -> Optional[User]:
        """Deactivate user account."""
        return self.update(user_id, UserUpdate(is_active=False))
    
    def activate(self, user_id: int) -> Optional[User]:
        """Activate user account."""
        return self.update(user_id, UserUpdate(is_active=True))
    
    def delete(self, user_id: int) -> bool:
        """Delete user account."""
        db_user = self.get_by_id(user_id)
        if not db_user:
            return False
        
        self.db.delete(db_user)
        self.db.commit()
        
        return True
    
    def count(self, role: Optional[UserRole] = None, is_active: Optional[bool] = None) -> int:
        """Count users with optional filtering."""
        query = self.db.query(User)
        
        if role:
            query = query.filter(User.role == role)
        
        if is_active is not None:
            query = query.filter(User.is_active == is_active)
        
        return query.count()
    
    def exists_by_username(self, username: str) -> bool:
        """Check if username exists."""
        return self.db.query(User).filter(User.username == username).first() is not None
    
    def exists_by_email(self, email: str) -> bool:
        """Check if email exists."""
        return self.db.query(User).filter(User.email == email).first() is not None
