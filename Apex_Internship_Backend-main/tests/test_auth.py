import pytest
from eth_account.messages import encode_defunct, defunct_hash_message
from fastapi import status
from fastapi.testclient import TestClient
from eth_account import Account
from web3 import Web3
from typing import Dict, Any, Optional
import json
import time
from unittest.mock import patch

# Enable asyncio support
pytestmark = pytest.mark.asyncio

# Helper function to sign a message with a private key
def sign_message(message: str, private_key: str) -> str:
    """Sign a message with a private key and return the signature."""
    account = Account.from_key(private_key)
    message_hash = defunct_hash_message(text=message)
    signed_message = Account.sign_message(
        signable_message={"message": message, "messageHash": message_hash.hex()},
        private_key=private_key
    )
    return signed_message.signature.hex()

async def test_health_check(client, mock_redis):
    """Test the health check endpoint."""
    # The health check endpoint should return 200 OK when Redis is available
    response = client.get("/api/health")
    assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
    data = response.json()
    assert data == {
        "status": "ok",
        "message": "Authentication service is running and connected to Redis"
    }

async def test_challenge_endpoint(client, test_account, mock_redis):
    """Test the challenge generation endpoint."""
    wallet_address = test_account.address.lower()
    
    # Get challenge
    response = client.post(
        "/api/challenge",
        json={"wallet_address": wallet_address}
    )
    
    assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
    data = response.json()
    assert "message" in data, "Response should contain 'message' field"
    assert "nonce" in data, "Response should contain 'nonce' field"
    assert len(data["nonce"]) > 0, "Nonce should not be empty"
    
    # Verify the message format
    expected_message = f"Sign this message to authenticate with Apex.\n\nNonce: {data['nonce']}"
    assert data["message"] == expected_message, \
        f"Unexpected message format: {data['message']}"

async def test_complete_auth_flow(client, test_account, mock_redis):
    """Test the complete authentication flow."""
    wallet_address = test_account.address.lower()
    
    # Debug: Print the wallet address and ADMIN_ALLOWLIST
    print(f"Test wallet address: {wallet_address}")
    from auth.config import settings
    print(f"ADMIN_ALLOWLIST: {settings.ADMIN_ALLOWLIST}")
    
    # Create a dictionary to simulate Redis storage
    redis_store = {}
    
    # Mock the set operation to store the nonce
    async def mock_set(key, value, ex=None):
        redis_store[key] = value
        return True
    
    # Mock the get operation to retrieve the nonce
    async def mock_get(key):
        return redis_store.get(key)
    
    # Mock the delete operation
    async def mock_delete(key):
        if key in redis_store:
            del redis_store[key]
            return 1
        return 0
    
    # Set up the mock Redis methods
    mock_redis.set = mock_set
    mock_redis.get = mock_get
    mock_redis.delete = mock_delete
    
    # 1. Get challenge - this will store the nonce in our mock Redis
    challenge_response = client.post(
        "/api/challenge",
        json={"wallet_address": wallet_address}
    )
    assert challenge_response.status_code == status.HTTP_200_OK, \
        f"Challenge failed: {challenge_response.text}"
        
    challenge_data = challenge_response.json()
    nonce = challenge_data["nonce"]
    message = challenge_data["message"]
    
    # 2. Sign the challenge message
    message_hash = encode_defunct(text=message)
    signature = test_account.sign_message(message_hash).signature.hex()
    
    # 3. Mock the verify_signature function to return True
    with patch('auth.routes.utils.verify_signature') as mock_verify:
        mock_verify.return_value = True
        
        # 4. Login with the signature
        login_response = client.post(
            "/api/login",
            json={
                "wallet_address": wallet_address,
                "signature": signature,
                "nonce": nonce
            }
        )
    
    assert login_response.status_code == status.HTTP_200_OK, \
        f"Login failed: {login_response.text}"
        
    token_data = login_response.json()
    assert "access_token" in token_data, "Response should contain 'access_token'"
    assert token_data["token_type"] == "bearer", "Token type should be 'bearer'"
    
    # 7. Verify the token
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    verify_response = client.get("/api/verify", headers=headers)
    
    assert verify_response.status_code == status.HTTP_200_OK, \
        f"Token verification failed: {verify_response.text}"
        
    verify_data = verify_response.json()
    assert verify_data["wallet_address"].lower() == wallet_address, \
        f"Wallet address mismatch: {verify_data['wallet_address']} != {wallet_address}"

async def test_invalid_signature(client, test_account, mock_redis):
    """Test login with an invalid signature."""
    wallet_address = test_account.address.lower()
    
    # 1. Get a valid challenge first
    challenge_response = client.post(
        "/api/challenge",
        json={"wallet_address": wallet_address}
    )
    assert challenge_response.status_code == status.HTTP_200_OK, \
        f"Challenge failed: {challenge_response.text}"
    challenge_data = challenge_response.json()
    
    # 2. Try to login with an invalid signature
    login_response = client.post(
        "/api/login",
        json={
            "wallet_address": wallet_address,
            "signature": "0x" + "a" * 130,  # Invalid signature
            "nonce": challenge_data["nonce"]
        }
    )
    
    assert login_response.status_code == status.HTTP_401_UNAUTHORIZED, \
        f"Expected 401 Unauthorized, got {login_response.status_code}: {login_response.text}"
    
    error_data = login_response.json()
    assert "detail" in error_data, "Error response should contain 'detail' field"
    assert "Invalid signature or nonce" in error_data["detail"], \
        f"Expected 'Invalid signature or nonce' in error, got: {error_data}"

async def test_expired_nonce(client, test_account, mock_redis):
    """Test login with an expired nonce."""
    wallet_address = test_account.address.lower()
    
    # 1. Get a valid challenge first
    challenge_response = client.post(
        "/api/challenge",
        json={"wallet_address": wallet_address}
    )
    assert challenge_response.status_code == status.HTTP_200_OK, \
        f"Challenge failed: {challenge_response.text}"
    challenge_data = challenge_response.json()
    
    # 2. Clear the Redis mock to simulate an expired nonce
    mock_redis.get.return_value = None
    
    # 3. Try to login with the expired nonce
    login_response = client.post(
        "/api/login",
        json={
            "wallet_address": wallet_address,
            "signature": "0x" + "a" * 130,  # Signature doesn't matter since nonce is expired
            "nonce": challenge_data["nonce"]
        }
    )
    
    assert login_response.status_code == status.HTTP_401_UNAUTHORIZED, \
        f"Expected 401 Unauthorized, got {login_response.status_code}: {login_response.text}"
    
    error_data = login_response.json()
    assert "detail" in error_data, "Error response should contain 'detail' field"
    assert "Invalid signature or nonce" in error_data["detail"], \
        f"Expected 'Invalid signature or nonce' in error, got: {error_data}"
