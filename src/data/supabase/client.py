import os
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

def get_supabase_client() -> Client:
    url: str = os.getenv("SUPABASE_URL", "")
    key: str = os.getenv("SUPABASE_KEY", "")
    
    if not url or not key:
        # Provide a dummy client or raise exception depending on strictness
        # For this prototype, we'll just let it fail if used without config
        pass
        
    return create_client(url, key)

# Singleton instance
supabase_client = get_supabase_client() if os.getenv("SUPABASE_URL") else None
