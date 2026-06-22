from fastapi import APIRouter
from pydantic import BaseModel
from services.ai_service import analyze_email_ai
from services.email_parser import extract_urls_from_email, extract_email_metadata
from services.virustotal_service import scan_url
from services.threat_scorer import calculate_email_threat_score
from services.pattern_analyzer import analyze_email_patterns, analyze_url_patterns
from services.email_forensics import analyze_email_headers
from services.ipqs_service import scan_email_ipqs
import re
from datetime import datetime, timezone

router = APIRouter()

class EmailRequest(BaseModel):
    email_text: str

@router.post("/scan/email")
async def scan_email_endpoint(req: EmailRequest):
    """Analyze email content for phishing threats."""
    text = req.email_text
    
    # Extract metadata and URLs
    metadata = extract_email_metadata(text)
    urls = extract_urls_from_email(text)

    # Run header forensics
    header_forensics = analyze_email_headers(text)

    # Extract sender email and check with IPQS
    sender_match = re.search(r'From:\s*.*?([\w.-]+@[\w.-]+)', text, re.IGNORECASE)
    ipqs_email_result = {}
    if sender_match:
        try:
            ipqs_email_result = await scan_email_ipqs(sender_match.group(1))
        except Exception:
            pass

    # Pre-scan for common phishing indicators
    text_lower = text.lower()
    pre_flags = []
    
    # Urgency indicators
    urgency_keywords = ["urgent", "immediately", "act now", "verify now", "confirm", "suspended", "account locked", 
                       "limited time", "urgent action", "unauthorized", "illegal activity", "at risk"]
    for keyword in urgency_keywords:
        if keyword in text_lower:
            pre_flags.append(f"⚠️ Urgency language: '{keyword}'")
            break
    
    # Credential requests
    credential_keywords = ["password", "verify identity", "confirm password", "credit card", "cvv", "social security",
                          "ssn", "bank account", "routing number", "username", "login credentials"]
    for keyword in credential_keywords:
        if keyword in text_lower:
            pre_flags.append(f"🔐 Requests personal/credential info")
            break
    
    # Spoofed sender indicators
    if "@" in metadata.get("sender", ""):
        sender_domain = metadata["sender"].split("@")[1].lower() if "@" in metadata["sender"] else ""
        suspicious_domains = ["paypal1", "amazom", "google-account", "apple-id", "microsoft-verify"]
        for sus_domain in suspicious_domains:
            if sus_domain in sender_domain:
                pre_flags.append(f"⚠️ Suspicious sender domain detected")
                break

    # Scan extracted URLs with VirusTotal (max 3 to avoid rate limits)
    url_results = []
    for url in urls[:3]:
        try:
            vt = await scan_url(url)
            pattern = analyze_url_patterns(url)
            url_results.append({
                "url": url,
                "malicious": vt.get("malicious", 0),
                "suspicious": vt.get("suspicious", 0),
                "total": vt.get("total_engines", 0),
                "pattern_flags": pattern.get("flags_count", 0)
            })
        except Exception as e:
            print(f"Error scanning URL {url}: {e}")
            url_results.append({"url": url, "malicious": 0, "suspicious": 0, "total": 0})

    # Add pattern analysis for the email
    email_patterns = analyze_email_patterns(text)

    # AI analysis for phishing (now with more context)
    ai_result = await analyze_email_ai(text)

    # Combine AI score with pattern score and header forensics and IPQS
    base_score = ai_result.get("risk_score", 0)
    pattern_boost = min(25, email_patterns.get("pattern_score", 0) * 0.25)
    header_boost = min(30, header_forensics.get("header_score", 0) * 0.3)

    ipqs_boost = 0
    if ipqs_email_result.get("disposable"):
        ipqs_boost += 20
    if ipqs_email_result.get("fraud_score", 0) > 75:
        ipqs_boost += 25
    if ipqs_email_result.get("spam_trap"):
        ipqs_boost += 20

    combined_score = min(100, base_score + pattern_boost + header_boost + ipqs_boost)
    ai_result["risk_score"] = combined_score

    # Ensure email text is available to the scorer
    ai_result["email_text"] = text
    threat = calculate_email_threat_score(ai_result)

    # Merge pre-detected flags with AI indicators and email pattern flags
    all_indicators = pre_flags + ai_result.get("indicators", []) + email_patterns.get("flags", [])
    all_indicators += header_forensics.get("flags", [])
    if ipqs_email_result.get("disposable"):
        all_indicators.append("Sender uses disposable/temporary email address")
    if ipqs_email_result.get("recent_abuse"):
        all_indicators.append("Sender email address has recent abuse reports")

    return {
        "metadata": metadata,
        "threat_score": threat["score"],
        "threat_level": threat["level"],
        "verdict": ai_result.get("verdict", "Unknown"),
        "summary": ai_result.get("summary", ""),
        "indicators": all_indicators,
        "recommended_action": ai_result.get("recommended_action", ""),
        "extracted_urls": url_results,
        "reasons": threat["reasons"],
        "pattern_analysis": email_patterns,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
