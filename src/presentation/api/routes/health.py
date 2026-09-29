from fastapi import APIRouter

router = APIRouter(prefix="/health", tags=["System"])

@router.get("/")
def health_check():
    """
    Health check endpoint for Koyeb deployment.
    """
    return {"status": "ok", "service": "netshield-core"}
