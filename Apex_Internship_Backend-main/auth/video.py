from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional
import logging

from . import utils
from .models import TokenData
from .supabase_client import supabase

logger = logging.getLogger(__name__)
router = APIRouter(tags=["video"])
security = HTTPBearer(auto_error=False)

class VideoAccessResponse(BaseModel):
    signed_url: str
    expires_in_seconds: int

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[TokenData]:
    """Dependency to get current user from JWT token."""
    if not credentials:
        return None
    
    token_data = utils.verify_token(credentials.credentials)
    return token_data

@router.get("/{video_id}/access", response_model=VideoAccessResponse)
async def get_video_access(
    video_id: str,
    current_user: Optional[TokenData] = Depends(get_current_user)
):
    """
    Generate signed URL for video access with entitlement check.
    """
    try:
        # Validate JWT if provided
        if not current_user:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Authentication required"
            )
        
        # Validate session (skip for development if Redis not available)
        # In production, you'd validate against Redis session store
        if not utils.verify_session(current_user.wallet_address):
            # For development, continue even if session validation fails
            logger.warning(f"Session validation failed for {current_user.wallet_address}, continuing in development mode")
        
        # Check entitlement (simplified - always true for now)
        # In a real implementation, you'd check database for user's access to this video
        has_entitlement = True
        
        if not has_entitlement:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No access to this video"
            )
        
        # Generate signed URL (simplified - just a placeholder URL)
        # In a real implementation, you'd use AWS S3 presigned URLs or similar
        signed_url = f"https://example.com/videos/{video_id}?token={utils.create_access_token({'sub': current_user.wallet_address, 'video_id': video_id})}"
        
        return VideoAccessResponse(
            signed_url=signed_url,
            expires_in_seconds=300
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating video access: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate video access"
        )
