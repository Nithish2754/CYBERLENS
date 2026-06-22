from fastapi import APIRouter
from pydantic import BaseModel
from services.virustotal_service import scan_url
from services.safebrowsing_service import check_url
from services.ai_service import analyze_url_ai
from services.threat_scorer import calculate_url_threat_score
from services.urlscan_service import scan_url as urlscan_scan
from services.pattern_analyzer import analyze_url_patterns
from services.dns_service import check_dns_reputation
from services.domain_age_service import analyze_domain_heuristics
from services.ipqs_service import scan_url_ipqs
from services.phishtank_service import check_phishtank
from services.ssl_service import analyze_ssl
from services.redirect_service import analyze_redirects
from urllib.parse import urlparse
import asyncio
from datetime import datetime, timezone

router = APIRouter()

class URLRequest(BaseModel):
    url: str

@router.post("/scan/url")
async def scan_url_endpoint(req: URLRequest):
    """Scan a URL for threats using VirusTotal, Safe Browsing, and AI analysis."""
    url = req.url.strip()
    if not url.startswith("http"):
        url = "https://" + url
    # Run pattern analysis instantly (no external API required)
    pattern_result = analyze_url_patterns(url)

    # Extract domain for DNS/domain heuristics
    parsed = urlparse(url)
    domain = parsed.netloc
    domain_result = analyze_domain_heuristics(domain)

    # Run VirusTotal, Safe Browsing, DNS reputation, SSL, IPQS, and PhishTank in parallel
    vt_result, sb_result, dns_result, ssl_result, ipqs_result, phishtank_result = await asyncio.gather(
        scan_url(url),
        check_url(url),
        check_dns_reputation(domain),
        analyze_ssl(url),
        scan_url_ipqs(url),
        check_phishtank(url),
        return_exceptions=True
    )

    # Log every result to terminal for debugging
    print(f"\n{'='*50}")
    print(f"URL: {url}")
    print(f"VT: {vt_result}")
    print(f"SafeBrowsing: {sb_result}")
    print(f"DNS: {dns_result}")
    print(f"SSL: {ssl_result}")
    print(f"IPQS: {ipqs_result}")
    print(f"PhishTank: {phishtank_result}")
    print(f"Pattern: {pattern_result}")
    print(f"Domain: {domain_result}")
    print(f"{'='*50}\n")

    # Handle exceptions from gather and normalize shapes
    if isinstance(vt_result, Exception):
        print(f"VT ERROR: {vt_result}")
        vt_result = {"malicious": 0, "suspicious": 0, "total_engines": 0}
    if isinstance(sb_result, Exception):
        print(f"SB ERROR: {sb_result}")
        sb_result = {"is_threat": False, "threat_types": []}
    if isinstance(dns_result, Exception):
        print(f"DNS ERROR: {dns_result}")
        dns_result = {"dns_score": 0, "flags": [], "resolved": True}
    if isinstance(ssl_result, Exception):
        print(f"SSL ERROR: {ssl_result}")
        ssl_result = {"has_ssl": True, "flags": [], "ssl_score": 0, "available": False}
    if isinstance(ipqs_result, Exception):
        print(f"IPQS ERROR: {ipqs_result}")
        ipqs_result = {"phishing": False, "risk_score": 0, "available": False}
    if isinstance(phishtank_result, Exception):
        print(f"PhishTank ERROR: {phishtank_result}")
        phishtank_result = {"in_database": False, "verified": False, "available": False}

    # Redirect analysis (sequential — needs to follow chain)
    redirect_result = {}
    try:
        redirect_result = await analyze_redirects(
            url,
            ssl_result=ssl_result,
            dns_result=dns_result,
            pattern_flags_count=pattern_result.get("flags_count", 0),
            vt_result=vt_result,
            sb_result=sb_result,
            phishtank_result=phishtank_result,
        )
    except Exception as e:
        print(f"Redirect analysis skipped: {e}")

    # Run URLScan (may take longer) but try to include results
    urlscan_result = {}
    try:
        urlscan_result = await urlscan_scan(url)
    except Exception as e:
        print(f"URLScan skipped: {e}")

    # Calculate master score including SSL, IPQS, PhishTank, and redirect analysis
    threat = calculate_url_threat_score(
        vt_result, sb_result,
        pattern_result, urlscan_result,
        dns_result, domain_result,
        ssl_result, ipqs_result,
        phishtank_result, redirect_result
    )
    ai_explanation = await analyze_url_ai(
        url,
        vt_result,
        sb_result,
        pattern_result.get('flags', []),
        dns_result,
        domain_result,
        threat_score=threat["score"],
        threat_level=threat["level"],
    )

    return {
        "url": url,
        "threat_score": threat["score"],
        "threat_level": threat["level"],
        "reasons": threat["reasons"],
        "ai_explanation": ai_explanation,
        "virustotal": vt_result,
        "safe_browsing": sb_result,
        "pattern_analysis": pattern_result,
        "domain_analysis": domain_result,
        "dns_analysis": dns_result,
        "ssl_analysis": ssl_result,
        "ipqs": ipqs_result,
        "phishtank": phishtank_result,
        "redirect_analysis": redirect_result,
        "urlscan": urlscan_result,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
