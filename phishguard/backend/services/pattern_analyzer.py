import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "signin", "password", "credential", "suspend",
    "urgent", "alert", "locked", "unusual", "activity"
]

TRUSTED_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "facebook.com", "twitter.com", "instagram.com",
    "linkedin.com", "github.com", "youtube.com", "netflix.com"
]

COMMON_BRAND_MISSPELLINGS = {
    "paypa": "PayPal", "paypa1": "PayPal", "paypai": "PayPal",
    "arnazon": "Amazon", "amazom": "Amazon", "amaz0n": "Amazon",
    "g00gle": "Google", "go0gle": "Google", "googie": "Google",
    "micros0ft": "Microsoft", "microsofi": "Microsoft",
    "appleid": "Apple", "app1e": "Apple",
    "faceb00k": "Facebook", "facebok": "Facebook",
    "netf1ix": "Netflix", "netfiix": "Netflix"
}

def analyze_url_patterns(url: str) -> dict:
    """Analyze URL for phishing patterns."""
    flags = []
    score = 0

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full_url = url.lower()

        # Check 1: IP address instead of domain
        ip_pattern = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain)
        if ip_pattern:
            flags.append("🚨 Uses raw IP address instead of domain name")
            score += 50

        # Check 2: URL length
        if len(url) > 100:
            flags.append(f"⚠️ Unusually long URL ({len(url)} characters)")
            score += 20
        elif len(url) > 75:
            flags.append(f"⚠️ Long URL ({len(url)} characters) — common in phishing")
            score += 8

        # Check 3: Multiple subdomains
        domain_parts = domain.replace("www.", "").split(".")
        if len(domain_parts) > 4:
            flags.append(f"🚨 Excessive subdomains ({len(domain_parts)-2} levels) — phishing tactic")
            score += 30

        # Check 4: @ symbol in URL
        if "@" in url:
            flags.append("🚨 URL contains @ symbol — browser ignores everything before it")
            score += 55

        # Check 5: Suspicious keywords in domain
        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in domain]
        if found_keywords:
            flags.append(f"⚠️ Suspicious keywords: {', '.join(found_keywords[:3])}")
            score += len(found_keywords) * 12

        # Check 6: Brand misspellings
        for misspelling, brand in COMMON_BRAND_MISSPELLINGS.items():
            if misspelling in domain:
                flags.append(f"🚨 Possible {brand} impersonation: '{misspelling}' in domain - BRAND IMPERSONATION — highest phishing signal")
                score += 60
                break

        # Check 7: Trusted brand in subdomain but different main domain
        for trusted in TRUSTED_DOMAINS:
            brand = trusted.split(".")[0]
            if brand in domain and trusted not in domain:
                flags.append(f"🚨 '{brand}' brand name used in fake domain — impersonation")
                score += 55
                break

        # Check 8: HTTP instead of HTTPS
        if parsed.scheme == "http":
            flags.append("⚠️ Non-secure HTTP connection (no SSL/TLS encryption)")
            score += 15

        # Check 9: Suspicious TLDs
        suspicious_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click", ".loan", ".work"]
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                flags.append(f"🚨 High-risk domain extension: {tld}")
                score += 25
                break

        # Check 10: Double slash redirect
        if "//" in path:
            flags.append("⚠️ Double slash in URL path — possible redirect trick")
            score += 15

        # Check 11: Hex encoding
        if "%" in url and url.count("%") > 3:
            flags.append("⚠️ Excessive URL encoding — hides malicious content")
            score += 20

        # Check 12: Numeric domain
        domain_name = domain.split(".")[0]
        if domain_name.isdigit():
            flags.append("🚨 Domain is entirely numeric — unusual and suspicious")
            score += 25

        # Check 13: Login/verify path combined with suspicious domain
        if any(kw in path for kw in ["login", "verify", "confirm", "secure", "account"]):
            if any(tld in domain for tld in [".xyz", ".tk", ".ml", ".top", ".click"]):
                flags.append("🚨 Login/verify page on high-risk domain — strong phishing indicator")
                score += 35

        # Check 14: Query parameters with sensitive names
        sensitive_params = ["user", "email", "password", "token", "key", "auth", "id"]
        query = parsed.query.lower()
        found_params = [p for p in sensitive_params if p + "=" in query]
        if found_params:
            flags.append(f"🚨 URL collects sensitive parameters: {', '.join(found_params)}")
            score += 20

        # Check 15: Domain age simulation (heuristic for auto-generated names)
        domain_name = domain.split(".")[0].replace("www", "")
        if len(domain_name) > 15 and any(c.isdigit() for c in domain_name):
            flags.append("⚠️ Domain appears auto-generated (long name with numbers)")
            score += 20

        # Check 16: Multiple suspicious signals combined = amplifier
        if len(flags) >= 3:
            amplifier = (len(flags) - 2) * 5
            score += min(20, amplifier)
            flags.append(f"⚠️ Multiple threat signals detected ({len(flags)} indicators) — high confidence phishing")

    except Exception as e:
        print(f"Pattern analysis error: {e}")

    score = min(100, score)
    return {
        "pattern_score": score,
        "flags": flags,
        "flags_count": len(flags)
    }


def analyze_email_patterns(email_text: str) -> dict:
    """Analyze email content for phishing patterns."""
    flags = []
    score = 0
    text_lower = email_text.lower()

    # Urgency phrases
    urgency_phrases = [
        "act now", "immediately", "urgent", "expires in", "hours left",
        "final warning", "last chance", "suspended", "terminated",
        "verify now", "confirm immediately", "account locked"
    ]
    found_urgency = [p for p in urgency_phrases if p in text_lower]
    if found_urgency:
        flags.append(f"⏰ Urgency tactics: '{found_urgency[0]}'")
        score += len(found_urgency) * 12

    # Credential requests
    credential_words = ["password", "credit card", "ssn", "social security",
                       "bank account", "pin number", "date of birth", "mother's maiden"]
    found_creds = [w for w in credential_words if w in text_lower]
    if found_creds:
        flags.append(f"🔐 Requests sensitive info: {', '.join(found_creds[:2])}")
        score += 45

    # Threat language
    threat_phrases = ["will be deleted", "permanently closed", "legal action",
                     "report to authorities", "law enforcement"]
    found_threats = [p for p in threat_phrases if p in text_lower]
    if found_threats:
        flags.append("⚠️ Threatening language to create fear")
        score += 20

    # Suspicious sender patterns
    sender_match = re.search(r'from:\s*(.+)', email_text, re.IGNORECASE)
    if sender_match:
        sender = sender_match.group(1).lower()
        for misspelling, brand in COMMON_BRAND_MISSPELLINGS.items():
            if misspelling in sender:
                flags.append(f"🚨 Sender impersonates {brand}")
                score += 55
                break
        if re.search(r'\d{4,}', sender):
            flags.append("⚠️ Sender has suspicious number sequence")
            score += 15

    # Mismatched reply-to
    from_match = re.search(r'from:\s*\S+@(\S+)', email_text, re.IGNORECASE)
    reply_match = re.search(r'reply-to:\s*\S+@(\S+)', email_text, re.IGNORECASE)
    if from_match and reply_match:
        if from_match.group(1).lower() != reply_match.group(1).lower():
            flags.append("🚨 Reply-To domain differs from From — phishing tactic")
            score += 40

    # Check: ALL CAPS words (urgency tactic)
    caps_words = re.findall(r'\b[A-Z]{4,}\b', email_text)
    caps_words = [w for w in caps_words if w not in ['FROM', 'SUBJECT', 'HTTP', 'HTTPS']]
    if len(caps_words) >= 3:
        flags.append(f"⚠️ Excessive capitalization for urgency: {', '.join(caps_words[:3])}")
        score += 15

    # Check: Fake unsubscribe links
    if "unsubscribe" in text_lower and "click here" in text_lower:
        flags.append("⚠️ Fake unsubscribe link — common phishing tactic to confirm active emails")
        score += 10

    # Check: Impersonating official departments
    official_terms = ["security team", "support team", "fraud department", 
                      "account team", "billing department", "verification team"]
    found_official = [t for t in official_terms if t in text_lower]
    if found_official:
        flags.append(f"🚨 Impersonates official department: '{found_official[0]}'")
        score += 25

    # Check: Multiple exclamation marks
    if email_text.count("!") >= 3:
        flags.append("⚠️ Multiple exclamation marks — psychological pressure tactic")
        score += 10

    # Check: Short time pressure
    time_pressure = ["24 hours", "48 hours", "2 hours", "1 hour", 
                     "24hrs", "within hours", "today only", "expires today"]
    found_time = [t for t in time_pressure if t in text_lower]
    if found_time:
        flags.append(f"⚠️ Time pressure tactic: '{found_time[0]}'")
        score += 20

    # Amplifier: multiple signals
    if len(flags) >= 4:
        score += min(25, (len(flags) - 3) * 6)

    score = min(100, score)
    return {
        "pattern_score": score,
        "flags": flags,
        "flags_count": len(flags)
    }
