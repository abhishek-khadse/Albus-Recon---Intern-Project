from fastapi import APIRouter, Depends, HTTPException, status, Request, Query, Header, Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, Dict, Any, Union, List
from datetime import datetime, timedelta, timezone
import logging

from . import models, utils
from .config import settings
from .models import TokenData
from .supabase_client import supabase
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["authentication"])
security = HTTPBearer(auto_error=False)

# --- HELPER FUNCTIONS ---

# --- MOCK STORAGE FOR DEVELOPMENT ---
mock_nonces = {}

def store_nonce(wallet_address: str, nonce: str, expires_in: int = 300) -> bool:
    """Store nonce in Supabase (Synchronous)."""
    # Use mock storage if in mock mode
    if hasattr(supabase, 'mock_mode') and supabase.mock_mode:
        mock_nonces[wallet_address.lower()] = {
            "nonce": nonce,
            "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat()
        }
        logger.info(f"Mock mode: Stored nonce for {wallet_address.lower()}")
        return True
    
    try:
        # 1. Delete existing nonce
        # FIX: Used .from_() instead of .table()
        # FIX: Removed 'await' because supabase-py is synchronous
        supabase.from_("nonces").delete().eq("wallet_address", wallet_address.lower()).execute()
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat()
        
        supabase.from_("nonces").insert({
            "wallet_address": wallet_address.lower(),
            "nonce": nonce,
            "expires_at": expires_at
        }).execute()

        return True
    except Exception as e:
        logger.error(f"Error storing nonce in Supabase: {e}")
        return False

def get_nonce(wallet_address: str) -> Optional[str]:
    """Get and delete nonce from Supabase (Synchronous)."""
    # Use mock storage if in mock mode
    if hasattr(supabase, 'mock_mode') and supabase.mock_mode:
        wallet_key = wallet_address.lower()
        if wallet_key in mock_nonces:
            nonce_data = mock_nonces[wallet_key]
            # Check if expired
            expires_at = datetime.fromisoformat(nonce_data["expires_at"])
            if datetime.now(timezone.utc) < expires_at:
                del mock_nonces[wallet_key]
                logger.info(f"Mock mode: Retrieved nonce for {wallet_key}")
                return nonce_data["nonce"]
            else:
                del mock_nonces[wallet_key]
                logger.info(f"Mock mode: Nonce expired for {wallet_key}")
        return None
    
    try:
        result = supabase.from_("nonces") \
            .select("nonce") \
            .eq("wallet_address", wallet_address.lower()) \
            .execute()
        
        if result.data and len(result.data) > 0:
            
            nonce = result.data[0].get("nonce")
            # Delete used nonce
            supabase.from_("nonces").delete().eq("wallet_address", wallet_address.lower()).execute()
            
            return nonce
        return None

    except Exception as e:
        logger.error(f"Error getting nonce from Supabase: {e}")
        return None

# --- DEPENDENCIES ---

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> TokenData:
    """Dependency to get current user from JWT token."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    token_data = utils.verify_token(token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token_data

class AddWalletRequest(BaseModel):
    wallet_address: str

async def require_admin(current_user: TokenData = Depends(get_current_user)):
    """
    Dependency to require admin privileges.
    Supports both wallet addresses and usernames.
    """
    try:
        # Check if ADMIN_WALLET_ADDRESS is configured (for wallet-based admin)
        admin_address = settings.ADMIN_WALLET_ADDRESS
        
        # Check if ADMIN_USERNAME is configured (for username-based admin)
        admin_username = getattr(settings, 'ADMIN_USERNAME', None)
        
        if not admin_address and not admin_username:
            logger.error("No admin credentials configured")
            raise HTTPException(
                status_code=500,
                detail="Server configuration error: No Admin credentials set"
            )

        # Check wallet address admin
        if admin_address and current_user.wallet_address:
            if current_user.wallet_address.lower() == admin_address.lower():
                return current_user
        
        # Check username admin
        if admin_username and current_user.username:
            if current_user.username.lower() == admin_username.lower():
                return current_user
        
        logger.warning(f"Unauthorized Admin Attempt by: {current_user.username or current_user.wallet_address}")
        raise HTTPException(
            status_code=403,
            detail="Admin privileges required"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in admin verification: {e}")
        raise HTTPException(status_code=500, detail="Admin verification failed")

# --- ROUTES ---

@router.get("/auth/challenge", response_model=models.ChallengeResponse)
async def get_challenge(
    request: Request,
    walletAddress: str = Query(..., description="Wallet address"),
    test_mode: bool = Query(False, description="Enable test mode")
):
    print(f"\n=== Challenge Request: {walletAddress} ===")
    
    try:
        wallet_address = walletAddress.lower().strip()
        
        if not utils.is_valid_ethereum_address(wallet_address):
            raise HTTPException(status_code=400, detail="Invalid Ethereum address")

        nonce = utils.generate_nonce()
        
        if not test_mode:
            if not store_nonce(wallet_address, nonce, settings.NONCE_EXPIRY):
                raise HTTPException(status_code=500, detail="Database error: Failed to store nonce")
        
        challenge_message = f"Sign this message to authenticate with Apex: {nonce}"
        
        return {
            "message": challenge_message,
            "nonce": nonce
        }
    
    except HTTPException as he:
        raise he
    
    except Exception as e:
        logger.error(f"Challenge error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
@router.post("/auth/login", response_model=models.Token)
async def login(
    login_data: models.LoginRequest,
    test_mode: bool = Query(False)
):
    logger.info(f"\n=== Traditional Login Request ===")
    logger.info(f"Received login_data: {login_data}")
    logger.info(f"Username: {login_data.username}")
    logger.info(f"Password: {'*' * len(login_data.password) if login_data.password else 'None'}")
    logger.info(f"Login data dict: {login_data.model_dump()}")
    
    try:
        # Traditional login only
        if login_data.username and login_data.password:
            # For demo purposes, accept any username/password
            # In production, you'd validate against a database
            token_data = {"sub": login_data.username}
            token = utils.create_access_token(token_data)
            
            return {
                "access_token": token,
                "token_type": "bearer",
                "wallet_address": login_data.username,
                "role": "student",
                "access_level": "basic"
            }
        else:
            logger.error(f"Missing credentials - Username: {login_data.username}, Password: {login_data.password}")
            raise HTTPException(status_code=400, detail="Username and password required")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Traditional login error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Login failed")

@router.post("/auth/login/web3", response_model=models.Token)
async def login_web3(
    login_data: models.Web3LoginRequest,
    test_mode: bool = Query(False)
):
    logger.info(f"\n=== Web3 Login Request ===")
    logger.info(f"Wallet: {login_data.wallet_address}")
    
    try:
        wallet_address = login_data.wallet_address.lower().strip()
        
        # 1. Get nonce
        nonce = get_nonce(wallet_address)
        if not nonce and not test_mode:
            raise HTTPException(status_code=401, detail="Challenge expired or not found")
            
        # If test mode, bypass actual signature check for simplicity
        if test_mode:
            is_valid = True
        else:
            # 2. Verify signature
            challenge_message = f"Sign this message to authenticate with Apex: {nonce}"
            # utils.verify_signature expects wallet_address, signature, message
            is_valid = utils.verify_signature(
                wallet_address=wallet_address,
                signature=login_data.signature,
                message=challenge_message
            )
            
        if not is_valid:
            raise HTTPException(status_code=401, detail="Invalid signature or nonce")
            
        # 3. Create token
        token_data = {"sub": wallet_address}
        token = utils.create_access_token(token_data)
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "wallet_address": wallet_address,
            "role": "student",
            "access_level": "basic"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Web3 login error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Web3 login failed")

@router.get("/auth/verify")
async def verify_endpoint(current_user: TokenData = Depends(get_current_user)):
    return {
        "status": "valid",
        "wallet_address": current_user.username or current_user.wallet_address,
        "username": current_user.username
    }

@router.post("/auth/logout")
async def logout_user(current_user: TokenData = Depends(get_current_user)):
    """
    Logout user and invalidate session.
    """
    try:
        # In a real implementation, you might:
        # - Add the token to a blacklist
        # - Remove the token from a database
        # - Invalidate the session in Redis
        # For now, we'll just log the logout
        
        logger.info(f"User {current_user.username or current_user.wallet_address} logged out")
        
        return {"message": "Logout successful", "status": "success"}
        
    except Exception as e:
        logger.error(f"Error during logout: {e}")
        raise HTTPException(status_code=500, detail="Logout failed")

@router.get("/admin/stats")
async def get_admin_stats(admin_user: TokenData = Depends(require_admin)):
    """
    Get administrative statistics.
    """
    try:
        # Mock admin statistics for development
        stats = {
            "totalUsers": 1247,
            "activeUsers": 892,
            "totalCourses": 12,
            "totalPoints": 2456780,
            "recentRegistrations": 23,
            "pendingApprovals": 5
        }
        
        logger.info(f"Admin ({admin_user.username}) accessed stats")
        return stats
        
    except Exception as e:
        logger.error(f"Error fetching admin stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch admin statistics")

@router.get("/admin/users/recent")
async def get_recent_users(admin_user: TokenData = Depends(require_admin)):
    """
    Get recent user registrations.
    """
    try:
        # Mock recent users data for development
        recent_users = [
            {
                "id": "user_1",
                "name": "Alice Johnson",
                "email": "alice@example.com",
                "role": "Student",
                "status": "active",
                "created_at": "2025-02-20T10:30:00Z"
            },
            {
                "id": "user_2", 
                "name": "Bob Smith",
                "email": "bob@example.com",
                "role": "Student",
                "status": "pending",
                "created_at": "2025-02-20T09:15:00Z"
            },
            {
                "id": "user_3",
                "name": "Charlie Davis",
                "email": "charlie@example.com", 
                "role": "Student",
                "status": "active",
                "created_at": "2025-02-20T08:45:00Z"
            },
            {
                "id": "user_4",
                "name": "Diana Wilson",
                "email": "diana@example.com",
                "role": "Student", 
                "status": "active",
                "created_at": "2025-02-20T07:30:00Z"
            },
            {
                "id": "user_5",
                "name": "Eve Brown",
                "email": "eve@example.com",
                "role": "Student",
                "status": "pending",
                "created_at": "2025-02-20T06:15:00Z"
            }
        ]
        
        logger.info(f"Admin ({admin_user.username}) accessed recent users")
        return {"users": recent_users}
        
    except Exception as e:
        logger.error(f"Error fetching recent users: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch recent users")

@router.get("/admin/logs")
async def get_system_logs(admin_user: TokenData = Depends(require_admin)):
    """
    Get system logs.
    """
    try:
        # Mock system logs for development
        logs = [
            {
                "timestamp": "2025-02-20T10:30:00Z",
                "level": "INFO",
                "message": "User Alice Johnson logged in"
            },
            {
                "timestamp": "2025-02-20T10:25:00Z", 
                "level": "INFO",
                "message": "New user registration: Eve Brown"
            },
            {
                "timestamp": "2025-02-20T10:20:00Z",
                "level": "WARNING", 
                "message": "Failed login attempt for invalid user"
            },
            {
                "timestamp": "2025-02-20T10:15:00Z",
                "level": "INFO",
                "message": "Course 'Web Security Basics' updated"
            },
            {
                "timestamp": "2025-02-20T10:10:00Z",
                "level": "ERROR",
                "message": "Database connection timeout"
            },
            {
                "timestamp": "2025-02-20T10:05:00Z",
                "level": "INFO",
                "message": "System backup completed successfully"
            },
            {
                "timestamp": "2025-02-20T10:00:00Z",
                "level": "INFO",
                "message": "User Bob Smith completed course module"
            }
        ]
        
        logger.info(f"Admin ({admin_user.username}) accessed system logs")
        return {"logs": logs}
        
    except Exception as e:
        logger.error(f"Error fetching system logs: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch system logs")

@router.post("/admin/users/{user_id}/{action}")
async def manage_user(
    user_id: str,
    action: str,
    admin_user: TokenData = Depends(require_admin)
):
    """
    Manage user actions (approve, suspend, delete, etc.).
    """
    try:
        valid_actions = ["approve", "suspend", "activate", "delete"]
        if action not in valid_actions:
            raise HTTPException(status_code=400, detail=f"Invalid action: {action}")
        
        logger.info(f"Admin ({admin_user.username}) performed {action} on user {user_id}")
        
        return {"message": f"User {action} completed successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error managing user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to manage user")

@router.post("/admin/allowlist/add", status_code=201)
async def admin_add_to_allowlist(
    payload: AddWalletRequest,
    admin_user: TokenData = Depends(require_admin) 
):
    """
    Only the Admin Wallet can add new users to the allowlist.
    """
    target_wallet = payload.wallet_address.lower().strip()
    
    if not utils.is_valid_ethereum_address(target_wallet):
        raise HTTPException(status_code=400, detail="Invalid Ethereum Address")

    logger.info(f"Admin ({admin_user.wallet_address}) adding {target_wallet} to allowlist")

    try:
        existing = supabase.from_("allowlist")\
            .select("wallet_address")\
            .eq("wallet_address", target_wallet)\
            .execute()
            
        if existing.data:
            return {"message": "Wallet already in allowlist", "wallet": target_wallet}

        supabase.from_("allowlist").insert({
            "wallet_address": target_wallet,
            "created_at": datetime.now(timezone.utc).isoformat()
        }).execute()
        
        return {"message": "Successfully added to allowlist", "wallet": target_wallet}
        
    except Exception as e:
        logger.error(f"Database error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update allowlist")


@router.post("/auth/logout")
async def logout(current_user: TokenData = Depends(get_current_user)):
    """
    Logout user and invalidate session.
    """
    success = utils.invalidate_session(current_user.wallet_address)
    if success:
        return {"message": "Successfully logged out"}
    else:
        return {"message": "Logout completed", "warning": "Session was not active"}

@router.get("/health")
async def health_check():
    try:
        supabase.from_("nonces").select("*").limit(1).execute()
        return {"status": "ok", "database": "connected"}
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={"status": "error", "detail": str(e)}
        )