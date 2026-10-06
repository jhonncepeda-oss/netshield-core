import os
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
import uuid
import tempfile
from src.domain.models.audit import Device
from src.service.audit_service import AuditService
from src.service.report_service import ReportService
from src.data.supabase.repositories.supabase_audit_repo import SupabaseAuditRepository
from src.data.supabase.repositories.supabase_device_repo import SupabaseDeviceRepository

router = APIRouter(prefix="/audit", tags=["Audit"])

@router.post("/run")
async def run_audit_endpoint(
    hostname: str = Form(...), 
    ip_address: str = Form(...), 
    os_version: str = Form(...), 
    user_id: str = Form(...),
    file: UploadFile = File(...)
):
    """
    Runs a security audit against an uploaded configuration file.
    """
    device = Device(
        device_id=str(uuid.uuid4()),
        hostname=hostname,
        ip_address=ip_address,
        os_version=os_version
    )
    
    # Save uploaded file to temp file to parse it
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        content = await file.read()
        temp_file.write(content)
        temp_filepath = temp_file.name

    try:
        audit_repo = SupabaseAuditRepository()
        device_repo = SupabaseDeviceRepository()
        service = AuditService(audit_repo, device_repo)
        
        report = service.run_audit(temp_filepath, device, user_id=user_id)
        summary = ReportService.generate_summary(report)
        return {"report": summary, "results": report.results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
