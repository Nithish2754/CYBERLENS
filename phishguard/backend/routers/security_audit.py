from fastapi import APIRouter
from pydantic import BaseModel
from services.security_audit_service import run_security_audit
from services.ai_service import summarize_full_audit
from services.ssllabs_service import check_ssl_grade
from services.securityheaders_service import check_security_headers_grade
from services.hibp_service import check_domain_breaches
from services.crtsh_service import search_certificate_transparency
from services.shodan_service import check_exposed_services
from urllib.parse import urlparse
import asyncio
from datetime import datetime, timezone

router = APIRouter()

class AuditRequest(BaseModel):
    url: str

@router.post("/audit")
async def audit_endpoint(req: AuditRequest):
    url = req.url.strip()
    if not url.startswith("http"):
        url = "https://" + url

    domain = urlparse(url).netloc

    # Run main audit + 4 fast services in parallel
    audit_result, headers_grade, breach_check, cert_transparency, shodan_check = await asyncio.gather(
        run_security_audit(url),
        check_security_headers_grade(url),
        check_domain_breaches(domain),
        search_certificate_transparency(domain),
        check_exposed_services(domain),
        return_exceptions=True
    )

    ai_summary = await summarize_full_audit(
        audit_result if not isinstance(audit_result, Exception) else {}
    )

    return {
        **(audit_result if not isinstance(audit_result, Exception) else {}),
        "ai_summary": ai_summary,
        "security_headers_grade": headers_grade if not isinstance(headers_grade, Exception) else {"available": False},
        "breach_history": breach_check if not isinstance(breach_check, Exception) else {"available": False},
        "certificate_transparency": cert_transparency if not isinstance(cert_transparency, Exception) else {"available": False},
        "exposed_services": shodan_check if not isinstance(shodan_check, Exception) else {"available": False},
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# Separate endpoint for slow SSL Labs scan (takes 1-3 minutes)
@router.post("/audit/ssl-deep-scan")
async def ssl_deep_scan_endpoint(req: AuditRequest):
    domain = urlparse(
        req.url if req.url.startswith("http") else "https://" + req.url
    ).netloc
    result = await check_ssl_grade(domain)
    return result
