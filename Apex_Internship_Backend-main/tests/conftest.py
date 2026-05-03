import os
import sys
import pytest
from fastapi.testclient import TestClient
from eth_account import Account
from unittest.mock import patch, MagicMock, AsyncMock
from typing import Generator, Any, Dict, Optional
import json

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Set up test environment variables before importing the app
test_wallet_address = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"  # Test account address in lowercase
os.environ.update({
    "TESTING": "True",
    "JWT_SECRET": "test-secret-key",
    "JWT_ALGORITHM": "HS256",
    "JWT_EXPIRY_HOURS": "24",
    "REDIS_URL": "redis://localhost:6379/1",  # This won't be used in tests
    # Include test wallet addresses in the allowlist
    "ADMIN_ALLOWLIST": f"0x0000000000000000000000000000000000000000,{test_wallet_address}",
    "BACKEND_CORS_ORIGINS": "http://testserver"
})

# Now import the app with the test environment variables
from main import app
from auth.config import settings

# Configure test settings
settings.JWT_SECRET = "test-secret-key"
settings.JWT_ALGORITHM = "HS256"
settings.JWT_EXPIRY_HOURS = 24
settings.REDIS_URL = "redis://localhost:6379/1"
# Ensure the test wallet address is in the ADMIN_ALLOWLIST
settings.ADMIN_ALLOWLIST = ["0x0000000000000000000000000000000000000000", test_wallet_address]
settings.BACKEND_CORS_ORIGINS = ["http://testserver"]

class AsyncMock(MagicMock):
    """Async mock class for mocking async functions."""
    async def __call__(self, *args, **kwargs):
        return super().__call__(*args, **kwargs)

@pytest.fixture(autouse=True)
def mock_redis(monkeypatch):
    """Mock Redis client for testing."""
    # Create a mock Redis client with async methods
    mock_redis = MagicMock()
    
    # Store test data
    test_data = {}
    
    # Configure async methods
    async def async_get(key):
        # Convert key to string if it's bytes
        key_str = key.decode('utf-8') if isinstance(key, bytes) else key
        return test_data.get(key_str)
    
    async def async_set(key, value, ex=None):
        # Convert key to string if it's bytes
        key_str = key.decode('utf-8') if isinstance(key, bytes) else key
        test_data[key_str] = value
        return True
    
    async def async_delete(key):
        # Convert key to string if it's bytes
        key_str = key.decode('utf-8') if isinstance(key, bytes) else key
        if key_str in test_data:
            del test_data[key_str]
            return 1
        return 0
    
    async def async_ping():
        return True
    
    # Set up the mock methods
    mock_redis.get.side_effect = async_get
    mock_redis.set.side_effect = async_set
    mock_redis.delete.side_effect = async_delete
    mock_redis.ping.side_effect = async_ping
    
    # Patch the Redis client in the routes module
    monkeypatch.setattr('auth.routes.redis_client', mock_redis)
    
    # Also patch the Redis.from_url to return our mock
    def mock_from_url(*args, **kwargs):
        return mock_redis
    
    monkeypatch.setattr('redis.Redis.from_url', mock_from_url)
    
    # Clear test data between tests
    test_data.clear()
    
    return mock_redis

@pytest.fixture(scope="function")
def client() -> TestClient:
    """Create a test client with overridden dependencies."""
    # Create test client
    with TestClient(app) as test_client:
        yield test_client

@pytest.fixture(scope="function")
def test_account() -> Account:
    """Create a test Ethereum account."""
    # Use a fixed private key for consistent test account
    private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    return Account.from_key(private_key)

@pytest.fixture(scope="function", autouse=True)
def cleanup():
    """Clean up after each test."""
    # Setup code if needed
    yield
    # Cleanup code if needed
