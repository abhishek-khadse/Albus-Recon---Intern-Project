import json
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Union
from jose import JWTError, jwt
from eth_account.messages import encode_defunct
from eth_account import Account
from eth_utils import to_checksum_address, is_address
import redis
from .config import settings
from .models import TokenData

# Initialize Redis client
try:
    redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    redis_client.ping()  # Test connection
    logger = logging.getLogger(__name__)
    logger.info("Redis connection established")
except Exception as e:
    logger = logging.getLogger(__name__)
    logger.error(f"Failed to connect to Redis: {e}")
    redis_client = None


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def is_valid_ethereum_address(address: str) -> bool:
    """
    Validates if a string is a valid Ethereum address.
    Uses eth_utils.is_address logic (checks structure and checksums).
    """
    if not address or not isinstance(address, str):
        return False
    return is_address(address)

def create_nonce() -> str:
    """Generate a secure random nonce."""

    return secrets.token_hex(32)

def generate_nonce() -> str:
    """Alias for create_nonce for backward compatibility."""
    return create_nonce()

def store_nonce(wallet_address: str, nonce: str, redis_client: redis.Redis) -> bool:
    """
    Store nonce in Redis with expiry.
    """
    if not redis_client:
        logger.error("Redis client is not available")
        return False
        
    try:
        key = f"nonce:{wallet_address.lower()}"
        return redis_client.setex(
            name=key,
            time=settings.NONCE_EXPIRY,
            value=nonce
        )
    except Exception as e:
        logger.error(f"Error storing nonce in Redis: {e}")
        return False

def verify_nonce(wallet_address: str, nonce: str, redis_client: redis.Redis) -> bool:
    """
    Verify and invalidate the nonce if valid.
    """
    if not redis_client:
        logger.error("Redis client is not available")
        return False
        
    try:
        key = f"nonce:{wallet_address.lower()}"
        stored_nonce = redis_client.getdel(key)
        if isinstance(stored_nonce, bytes):
            stored_nonce = stored_nonce.decode('utf-8')
            
        return stored_nonce is not None and stored_nonce == nonce
    except Exception as e:
        logger.error(f"Error verifying nonce: {e}")
        return False

def create_access_token(
    data: Dict[str, Any], 
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT token with the given data and store session in Redis.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta 
        else timedelta(hours=settings.JWT_EXPIRY_HOURS)
    )
    
    to_encode.update({"exp": expire})
    
    try:
        token = jwt.encode(
            to_encode, 
            settings.JWT_SECRET, 
            algorithm=settings.JWT_ALGORITHM
        )
        
        # Store session in Redis to prevent multiple sessions
        if redis_client and 'sub' in to_encode:
            wallet_address = to_encode['sub']
            session_key = f"session:{wallet_address}"
            redis_client.setex(
                name=session_key,
                time=settings.JWT_EXPIRY_HOURS * 3600,  # Convert to seconds
                value=token
            )
            logger.info(f"Session created for wallet: {wallet_address}")
        
        return token
    except JWTError as e:
        logger.error(f"Error creating JWT token: {e}")
        raise

def verify_token(token: str) -> Optional[TokenData]:
    """
    Verify JWT token and return token data if valid.
    Also checks if the token is the active session in Redis.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM]
        )
        sub = payload.get("sub")
        if not sub:
            logger.warning("No subject in token")
            return None

        # Check if this is a wallet address or username
        if is_address(sub):
            # It's a wallet address
            wallet_address = sub
            # Check if this token is the active session in Redis
            if redis_client:
                session_key = f"session:{wallet_address}"
                active_token = redis_client.get(session_key)
                if active_token != token:
                    logger.warning(f"Token mismatch for wallet {wallet_address}. Possible session hijack.")
                    return None
            return TokenData(wallet_address=wallet_address)
        else:
            # It's a username
            username = sub
            # Check if this token is the active session in Redis
            if redis_client:
                session_key = f"session:{username}"
                active_token = redis_client.get(session_key)
                if active_token != token:
                    logger.warning(f"Token mismatch for username {username}. Possible session hijack.")
                    return None
            return TokenData(username=username)
        
    except JWTError as e:
        logger.error(f"JWT verification error: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during token verification: {e}")
        return None

def invalidate_session(wallet_address: str) -> bool:
    """
    Invalidate user session by removing from Redis.
    """
    if not redis_client:
        logger.warning("Redis not available for session invalidation")
        return False
        
    try:
        session_key = f"session:{wallet_address.lower()}"
        result = redis_client.delete(session_key)
        if result:
            logger.info(f"Session invalidated for wallet: {wallet_address}")
            return True
        else:
            logger.warning(f"No active session found for wallet: {wallet_address}")
            return False
    except Exception as e:
        logger.error(f"Error invalidating session: {e}")
        return False

def verify_signature(
    wallet_address: str, 
    signature: str, 
    message: str, 
    redis_client: redis.Redis = None
) -> bool:
    """
    Verify the Ethereum signature and nonce using EIP-191 personal_sign.
    """


    if not is_address(wallet_address):
        logger.warning(f"Invalid wallet address format: {wallet_address}")
        return False
        
    try:

        nonce = None
        
        if "Nonce: " in message:
            for line in message.split('\n'):
                if line.startswith('Nonce: '):
                    nonce = line.split('Nonce: ')[1].strip()
                    break
        

        if not nonce and "Apex: " in message:
            parts = message.split("Apex: ")
            if len(parts) > 1:
                nonce = parts[1].strip()
        

        if not nonce and len(message.strip()) == 64: 
             nonce = message.strip()

        if not nonce:
            logger.warning(f"No nonce found in message: '{message}'")
            return False

            
        try:
            message_hash = encode_defunct(text=message)
            
            signature_clean = signature
            if signature_clean.startswith('0x'):
                signature_clean = signature_clean[2:]
            
            if len(signature_clean) != 130:
                logger.error(f"Invalid signature length: {len(signature_clean)}, expected 130")
                return False
            
            try:
                recovered_address = Account.recover_message(
                    signable_message=message_hash,
                    signature=signature_clean
                )
                
                is_valid = to_checksum_address(recovered_address) == to_checksum_address(wallet_address)
                
                if is_valid:
                    logger.info(f"Successfully verified signature for wallet: {wallet_address}")
                else:
                    logger.warning(f"Signature mismatch. Recovered: {recovered_address}, Expected: {wallet_address}")
                    
                return is_valid
            except ValueError as ve:
                try:
                    signature_bytes = bytes.fromhex(signature_clean)
                    recovered_address = Account.recover_message(
                        signable_message=message_hash,
                        signature=signature_bytes
                    )
                    return to_checksum_address(recovered_address) == to_checksum_address(wallet_address)
                except Exception as bytes_error:
                    logger.error(f"Error with bytes format: {bytes_error}")
                    raise ve
                    
        except Exception as sig_error:
            logger.error(f"Error during signature recovery: {sig_error}")
            return False
        
    except Exception as e:
        logger.error(f"Error verifying signature: {e}")
        return False

verify_signature.nonces = set()