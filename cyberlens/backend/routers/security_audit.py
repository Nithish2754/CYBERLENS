from fastapi import APIRouter
from pydantic import BaseModel
from services.advanced_security_service import run_advanced_security_audit
from services.ai_service import summarize_full_audit
from urllib.parse import urlparse

router = APIRouter()

class AuditRequest(BaseModel):
    url: str

@router.post("/audit")
async def audit_endpoint(req: AuditRequest):
    url = req.url.strip()
    if not url.startswith("http"):
        url = "https://" + url

    audit_result = await run_advanced_security_audit(url)
    ai_summary = await summarize_full_audit(audit_result)
    audit_result["ai_summary"] = ai_summary
    return audit_result

@router.post("/security-audit")
async def security_audit_endpoint(req: AuditRequest):
    return await audit_endpoint(req)

