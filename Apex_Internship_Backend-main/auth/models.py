from pydantic import BaseModel, Field, field_validator, model_validator, ConfigDict
from typing import Optional, List, Dict, Any
from eth_utils import is_address, to_checksum_address


class ChallengeRequest(BaseModel):
    wallet_address: str = Field(..., description="Ethereum wallet address")
    
    @field_validator('wallet_address')
    @classmethod

    def validate_ethereum_address(cls, v: str) -> str:
        if not is_address(v):
            raise ValueError("Invalid Ethereum address")
        return to_checksum_address(v)

class ChallengeResponse(BaseModel):
    message: str
    nonce: str

class Web3LoginRequest(BaseModel):
    wallet_address: str = Field(..., description="Ethereum wallet address")
    signature: str = Field(..., description="Cryptographic signature of the challenge message")
    
    @field_validator('wallet_address')
    @classmethod
    def validate_ethereum_address(cls, v: str) -> str:
        if not is_address(v):
            raise ValueError("Invalid Ethereum address")
        return to_checksum_address(v)

class LoginRequest(BaseModel):
    username: str = Field(..., description="Username for traditional login")
    password: str = Field(..., description="Password for traditional login")
    
    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "username": "user@example.com",
                "password": "password123"
            }
        }
    )

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    username: Optional[str] = None
    wallet_address: Optional[str] = None
