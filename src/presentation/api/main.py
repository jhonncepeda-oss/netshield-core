from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.presentation.api.routes import health, audit, export
import os

app = FastAPI(
    title="NetShield Core API",
    description="API for network device security auditing",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(audit.router)
app.include_router(export.router)

@app.on_event("startup")
async def startup_event():
    # Verify environment variables
    if not os.getenv("SUPABASE_URL") or not os.getenv("SUPABASE_KEY"):
        print("WARNING: Supabase credentials not found. Database operations will fail.")
