def calculate_url_threat_score(
    vt: dict,
    sb: dict,
    pattern: dict = None,
    urlscan: dict = None,
    dns_result: dict = None,
    domain_result: dict = None,
    ssl_result: dict = None,
    ipqs_result: dict = None,
    phishtank_result: dict = None,
    redirect_result: dict = None,
) -> dict:
    score = 0
    reasons = []
    signal_count = 0

    # VirusTotal (weight: high when available)
    malicious = vt.get("malicious", 0)
    total = max(vt.get("total_engines", 1), 1)
    if malicious > 0:
        vt_score = min(70, malicious * 12)
        score += vt_score
        reasons.append(f"{malicious}/{total} security engines flagged as malicious")
        signal_count += 1
    if vt.get("reputation", 0) < -10:
        score += 15
        reasons.append("Poor VirusTotal reputation score")

    # Safe Browsing (weight: very high — Google's own data)
    if sb.get("is_threat"):
        score += 40
        signal_count += 1
        for t in sb.get("threat_types", []):
            reasons.append(f"Google Safe Browsing: {t.replace('_', ' ').title()}")

    # Pattern analysis (weight: primary signal for new URLs)
    if pattern:
        raw = pattern.get("pattern_score", 0)
        contribution = raw * 0.75
        score += contribution
        signal_count += 1 if raw > 20 else 0
        for flag in pattern.get("flags", [])[:4]:
            reasons.append(flag)

    # Domain heuristics
    if domain_result:
        h_score = domain_result.get("heuristic_score", 0)
        score += h_score * 0.4
        signal_count += 1 if h_score > 20 else 0
        for flag in domain_result.get("flags", [])[:2]:
            reasons.append(flag)

    # DNS reputation
    if dns_result:
        score += dns_result.get("dns_score", 0) * 0.5
        if not dns_result.get("resolved", True):
            score += 20
            signal_count += 1
        for flag in dns_result.get("flags", [])[:2]:
            reasons.append(flag)

    # PhishTank
    if phishtank_result and phishtank_result.get("in_database"):
        score += 60
        signal_count += 1
        if phishtank_result.get("verified"):
            score += 20
            reasons.append("VERIFIED phishing URL in PhishTank database")
        else:
            reasons.append("URL found in PhishTank phishing database")

    # IPQualityScore
    if ipqs_result:
        ipqs_score = ipqs_result.get("risk_score", 0)
        if ipqs_result.get("phishing"):
            score += 50
            signal_count += 1
            reasons.append("IPQualityScore confirmed phishing URL")
        elif ipqs_result.get("malware"):
            score += 45
            signal_count += 1
            reasons.append("IPQualityScore detected malware")
        elif ipqs_result.get("suspicious") or ipqs_score > 75:
            score += 30
            signal_count += 1
            reasons.append(f"IPQualityScore risk: {ipqs_score}/100")
        if ipqs_result.get("short_link"):
            score += 15
            reasons.append("URL is a disguised short link redirect")
        if not ipqs_result.get("dns_valid", True):
            score += 20
            reasons.append("Domain has invalid DNS records")

    # SSL analysis
    if ssl_result:
        ssl_score = ssl_result.get("ssl_score", 0)
        score += ssl_score * 0.3
        for flag in ssl_result.get("flags", [])[:2]:
            reasons.append(flag)
            signal_count += 1 if ssl_score > 30 else 0

    # URLScan
    if urlscan and not urlscan.get("error"):
        if urlscan.get("malicious"):
            score += 30
            signal_count += 1
            reasons.append("URLScan.io confirmed malicious")
        elif urlscan.get("score", 0) > 50:
            score += 15
            reasons.append(f"URLScan.io risk score: {urlscan.get('score')}/100")

    # Redirect chain
    if redirect_result:
        r_score = redirect_result.get("redirect_score", 0)
        score += r_score * 0.5
        signal_count += 1 if r_score > 20 else 0
        for flag in redirect_result.get("flags", [])[:2]:
            reasons.append(flag)

    # Multi-signal amplifier: if 3+ independent sources agree = very high confidence
    if signal_count >= 3:
        amplifier = (signal_count - 2) * 8
        score += min(25, amplifier)
        reasons.append(f"{signal_count} independent detection sources flagged this URL")

    score = min(100, score)

    # Thresholds
    if score < 15: level = "SAFE"
    elif score < 35: level = "LOW RISK"
    elif score < 55: level = "MEDIUM RISK"
    elif score < 75: level = "HIGH RISK"
    else: level = "CRITICAL THREAT"

    if not reasons:
        reasons.append("No threats detected across all security engines")

    return {"score": score, "level": level, "reasons": reasons}


def calculate_email_threat_score(ai_result: dict) -> dict:
    """Calculate threat score for email based on AI analysis."""
    score = ai_result.get("risk_score", 0)
    indicators = ai_result.get("indicators", [])

    # Email-specific threat detection
    urgency_keywords = ["urgent", "immediately", "now", "verify", "confirm", "act now", "suspended", "limited time"]
    
    email_text = ai_result.get("email_text", "").lower()
    if any(keyword in email_text for keyword in urgency_keywords):
        score = min(100, score + 10)
        indicators.append("⚠️ High-pressure urgency language detected")
    
    # Credential request detection
    credential_keywords = ["password", "verify", "confirm identity", "credit card", "ssn", "bank", "username", "login"]
    if any(keyword in email_text for keyword in credential_keywords):
        score = min(100, score + 15)
        indicators.append("🚨 Credential/personal information request detected")
    
    # Suspicious sender detection
    if ai_result.get("verdict") == "Phishing":
        score = max(score, 75)  # Ensure phishing emails score high

    if score < 20:
        level = "SAFE"
    elif score < 35:  # Lowered from 40
        level = "LOW RISK"
    elif score < 60:  # Lowered from 65
        level = "MEDIUM RISK"
    elif score < 80:  # Lowered from 85
        level = "HIGH RISK"
    else:
        level = "CRITICAL THREAT"

    return {"score": score, "level": level, "reasons": indicators}
