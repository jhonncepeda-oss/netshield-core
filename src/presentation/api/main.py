from fastapi import FastAPI
from src.presentation.api.routes import health, audit
import os

app = FastAPI(
    title="NetShield Core API",
    description="API for network device security auditing",
    version="1.0.0"
)

app.include_router(health.router)
app.include_router(audit.router)

@app.on_event("startup")
async def startup_event():
    # Verify environment variables
    if not os.getenv("SUPABASE_URL") or not os.getenv("SUPABASE_KEY"):
        print("WARNING: Supabase credentials not found. Database operations will fail.")
