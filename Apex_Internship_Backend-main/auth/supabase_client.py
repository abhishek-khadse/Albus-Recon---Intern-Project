import os
import logging
from typing import Optional, List, Dict, Any, Union
from eth_utils import to_checksum_address, is_address
from dotenv import load_dotenv
from supabase import create_client, Client

# Configure logging
logger = logging.getLogger(__name__)

class SupabaseWrapper:
    def __init__(self):
        load_dotenv()
        
        self.supabase_url = os.getenv("SUPABASE_URL")
        self.supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        self.table_name = os.getenv("SUPABASE_ALLOWLIST_TABLE", "allowlist")
        self.mock_mode = False
        
        if not self.supabase_url or not self.supabase_key or "your-project-id" in self.supabase_url:
            logger.warning("Supabase not configured - using mock mode for development")
            self.mock_mode = True
            self.client = None
        else:
            # Initialize the OFFICIAL client
            self.client: Client = create_client(self.supabase_url, self.supabase_key)

    def __getattr__(self, name):
        """
        Magic method: If you call a method like .from_() or .table() that 
        isn't defined here, pass it directly to the official client.
        This fixes the 'AttributeError' you were seeing!
        """
        return getattr(self.client, name)

    def _normalize_address(self, address: str) -> Optional[str]:
        """Normalize Ethereum address to checksum format."""
        try:
            if not address or not is_address(address):
                return None
            return to_checksum_address(address)
        except Exception as e:
            logger.error(f"Error normalizing address {address}: {e}")
            return None

    # Note: Removed 'async' because the standard Python Supabase client is synchronous.
    # If you use 'await' in routes.py with these, you should remove the 'await' there.
    
    def is_wallet_allowlisted(self, address: str) -> bool:
        """Check if a wallet is in the allowlist."""
        normalized = self._normalize_address(address)
        if not normalized:
            return False

        if self.mock_mode:
            # In mock mode, allow any wallet for testing
            logger.info(f"Mock mode: Allowing wallet {normalized}")
            return True

        try:
            # Use official client syntax
            response = self.client.from_(self.table_name)\
                .select("wallet_address")\
                .eq("wallet_address", normalized)\
                .execute()
            
            # Check if we got any data back
            return len(response.data) > 0
        except Exception as e:
            logger.error(f"Error checking allowlist: {e}")
            return False

    def add_wallet_to_allowlist(self, address: str) -> Dict[str, Any]:
        """Add a wallet to the allowlist."""
        normalized = self._normalize_address(address)
        if not normalized:
            return {"error": "Invalid Ethereum address"}

        if self.mock_mode:
            return {"message": "Mock mode: Wallet would be added to allowlist", "wallet_address": normalized}

        # Check if already exists
        if self.is_wallet_allowlisted(normalized):
            return {"message": "Wallet already in allowlist", "wallet_address": normalized}

        try:
            response = self.client.from_(self.table_name)\
                .insert({"wallet_address": normalized})\
                .execute()
                
            return {"message": "Wallet added to allowlist", "wallet_address": normalized}
        except Exception as e:
            logger.error(f"Error adding wallet: {e}")
            return {"error": str(e)}

    def get_allowlist_wallets(self) -> List[str]:
        """Get all wallets in the allowlist."""
        if self.mock_mode:
            # Return some mock addresses for testing
            return ["0x1234567890123456789012345678901234567890"]
            
        try:
            response = self.client.from_(self.table_name)\
                .select("wallet_address")\
                .execute()
            
            if response.data:
                return [item.get("wallet_address") for item in response.data]
            return []
        except Exception as e:
            logger.error(f"Error fetching allowlist: {e}")
            return []

# Create the singleton instance
supabase = SupabaseWrapper()