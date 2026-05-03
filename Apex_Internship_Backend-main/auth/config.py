import os
from typing import List
from dotenv import load_dotenv
from functools import lru_cache

load_dotenv()

class Settings:
    def __init__(self):
        """Initialize settings from environment variables."""
        
        self.PROJECT_NAME = "Apex Auth Backend"
        self.API_V1_STR = "/api"
        
        # JWT Configuration
        self.JWT_SECRET = os.getenv("JWT_SECRET")
        if not self.JWT_SECRET:
            raise ValueError("JWT_SECRET must be set in environment variables")
            
        self.JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
        self.JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", "24"))
        
        self.ADMIN_WALLET_ADDRESS = os.getenv("ADMIN_WALLET_ADDRESS")
        if self.ADMIN_WALLET_ADDRESS:
            self.ADMIN_WALLET_ADDRESS = self.ADMIN_WALLET_ADDRESS.lower().strip()
        
        self.ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
        if self.ADMIN_USERNAME:
            self.ADMIN_USERNAME = self.ADMIN_USERNAME.lower().strip()
        
        # Supabase Configuration
        self.SUPABASE_URL = os.getenv("SUPABASE_URL")
        self.SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        
        if not self.SUPABASE_URL or not self.SUPABASE_SERVICE_ROLE_KEY:
            raise ValueError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set in environment variables")
        
        # CORS Configuration
        cors_origins = os.getenv("BACKEND_CORS_ORIGINS", "http://localhost:5173,http://localhost:3000")
        self.BACKEND_CORS_ORIGINS = [origin.strip() for origin in cors_origins.split(",") if origin.strip()]
        
        # Nonce expiry in seconds (default 5 minutes)
        self.NONCE_EXPIRY = int(os.getenv("NONCE_EXPIRY", "300"))
        
        # Redis Configuration
        # Fixed: Removed self reference, added default None or localhost string
        self.REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
        
        # Allowlist Configuration
        # Fixed: Removed self reference
        self.ENABLE_ALLOWLIST = os.getenv("ENABLE_ALLOWLIST", "False").lower() in ('true', '1', 't')

        admin_allowlist = os.getenv("ADMIN_ALLOWLIST")
        self.ADMIN_ALLOWLIST: List[str] = []
        if admin_allowlist:
            self.ADMIN_ALLOWLIST = [x.strip() for x in admin_allowlist.split(",") if x.strip()]


@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()