import httpx
import ssl
import socket
import asyncio
from urllib.parse import urlparse
from datetime import datetime


async def run_security_audit(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "")
    findings = []
    passed = []
    score = 100  # Start at 100, deduct for each issue found

    async with httpx.AsyncClient(
        timeout=15, follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; PhishGuard-Audit/1.0)"}
    ) as client:
        try:
            response = await client.get(url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            content = response.text.lower()

            # ── 1. HTTPS ENFORCEMENT ──
            if parsed.scheme == "http":
                findings.append({
                    "severity": "HIGH",
                    "category": "Encryption",
                    "issue": "Site does not enforce HTTPS",
                    "recommendation": "Redirect all HTTP traffic to HTTPS and obtain an SSL certificate"
                })
                score -= 20
            else:
                passed.append("Site uses HTTPS")

            # ── 2. HSTS HEADER ──
            if "strict-transport-security" not in headers:
                findings.append({
                    "severity": "MEDIUM",
                    "category": "Security Headers",
                    "issue": "Missing Strict-Transport-Security (HSTS) header",
                    "recommendation": "Add HSTS header to force browsers to always use HTTPS, preventing downgrade attacks"
                })
                score -= 8
            else:
                passed.append("HSTS header present")

            # ── 3. CONTENT SECURITY POLICY ──
            if "content-security-policy" not in headers:
                findings.append({
                    "severity": "MEDIUM",
                    "category": "Security Headers",
                    "issue": "Missing Content-Security-Policy (CSP) header",
                    "recommendation": "Add a CSP header to prevent cross-site scripting (XSS) and code injection attacks"
                })
                score -= 8
            else:
                passed.append("Content-Security-Policy header present")

            # ── 4. X-FRAME-OPTIONS ──
            if "x-frame-options" not in headers:
                findings.append({
                    "severity": "MEDIUM",
                    "category": "Security Headers",
                    "issue": "Missing X-Frame-Options header",
                    "recommendation": "Add X-Frame-Options to prevent clickjacking attacks where your site is embedded in a malicious iframe"
                })
                score -= 6
            else:
                passed.append("X-Frame-Options header present")

            # ── 5. X-CONTENT-TYPE-OPTIONS ──
            if "x-content-type-options" not in headers:
                findings.append({
                    "severity": "LOW",
                    "category": "Security Headers",
                    "issue": "Missing X-Content-Type-Options header",
                    "recommendation": "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing attacks"
                })
                score -= 4
            else:
                passed.append("X-Content-Type-Options header present")

            # ── 6. SERVER VERSION DISCLOSURE ──
            server_header = headers.get("server", "")
            if server_header and any(c.isdigit() for c in server_header):
                findings.append({
                    "severity": "LOW",
                    "category": "Information Disclosure",
                    "issue": f"Server header reveals version info: '{server_header}'",
                    "recommendation": "Hide or generalize the Server header to avoid revealing software versions attackers could target"
                })
                score -= 5
            elif server_header:
                passed.append("Server header does not leak version details")

            # ── 7. MIXED CONTENT CHECK ──
            if parsed.scheme == "https" and 'src="http://' in content:
                findings.append({
                    "severity": "MEDIUM",
                    "category": "Mixed Content",
                    "issue": "Page loads some resources over insecure HTTP while on HTTPS",
                    "recommendation": "Ensure ALL resources (images, scripts, styles) load via HTTPS to avoid mixed content warnings"
                })
                score -= 10

            # ── 8. EXPOSED ADMIN/SENSITIVE PATHS ──
            sensitive_paths = ["/admin", "/.env", "/wp-admin", "/.git", "/config.php", "/phpinfo.php"]
            exposed = []
            for path in sensitive_paths:
                try:
                    check = await client.get(url.rstrip("/") + path, timeout=5)
                    if check.status_code == 200:
                        exposed.append(path)
                except Exception:
                    pass
            if exposed:
                findings.append({
                    "severity": "HIGH",
                    "category": "Exposed Endpoints",
                    "issue": f"Potentially sensitive paths are publicly accessible: {', '.join(exposed)}",
                    "recommendation": "Restrict access to admin panels and configuration files; they should never be publicly reachable"
                })
                score -= 25
            else:
                passed.append("No common sensitive paths exposed")

            # ── 9. COOKIE SECURITY ──
            set_cookie = headers.get("set-cookie", "")
            if set_cookie:
                if "secure" not in set_cookie.lower():
                    findings.append({
                        "severity": "MEDIUM",
                        "category": "Cookie Security",
                        "issue": "Cookies are not marked as Secure",
                        "recommendation": "Add the 'Secure' flag to cookies so they're only sent over HTTPS connections"
                    })
                    score -= 6
                if "httponly" not in set_cookie.lower():
                    findings.append({
                        "severity": "MEDIUM",
                        "category": "Cookie Security",
                        "issue": "Cookies are not marked as HttpOnly",
                        "recommendation": "Add the 'HttpOnly' flag to cookies to prevent JavaScript-based theft via XSS"
                    })
                    score -= 6
                if "samesite" not in set_cookie.lower():
                    findings.append({
                        "severity": "LOW",
                        "category": "Cookie Security",
                        "issue": "Cookies do not specify SameSite attribute",
                        "recommendation": "Add SameSite=Strict or Lax to cookies to reduce CSRF attack risk"
                    })
                    score -= 4

            # ── 10. FORM SECURITY ──
            if "<form" in content and parsed.scheme == "http":
                findings.append({
                    "severity": "HIGH",
                    "category": "Form Security",
                    "issue": "Forms are submitted over an insecure HTTP connection",
                    "recommendation": "Serve all pages with forms over HTTPS to protect submitted data in transit"
                })
                score -= 15

        except Exception as e:
            findings.append({
                "severity": "INFO",
                "category": "Connectivity",
                "issue": f"Could not fully analyze site: {str(e)}",
                "recommendation": "Verify the site is reachable and try again"
            })

    # ── 11. SSL CERTIFICATE DEEP CHECK ──
    if parsed.scheme == "https":
        try:
            loop = asyncio.get_event_loop()
            def get_cert():
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=8) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        return ssock.getpeercert(), ssock.version()

            cert, tls_version = await loop.run_in_executor(None, get_cert)

            if tls_version in ["TLSv1", "TLSv1.1"]:
                findings.append({
                    "severity": "HIGH",
                    "category": "Encryption",
                    "issue": f"Site uses outdated TLS version: {tls_version}",
                    "recommendation": "Upgrade server to support only TLS 1.2 or TLS 1.3; older versions have known vulnerabilities"
                })
                score -= 15
            else:
                passed.append(f"Uses modern TLS version: {tls_version}")

            expire_str = cert.get("notAfter", "")
            if expire_str:
                try:
                    expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expire_date - datetime.utcnow()).days
                    if days_left < 30:
                        findings.append({
                            "severity": "MEDIUM",
                            "category": "SSL Certificate",
                            "issue": f"SSL certificate expires in {days_left} days",
                            "recommendation": "Renew the SSL certificate soon to avoid service disruption and browser warnings"
                        })
                        score -= 10
                    else:
                        passed.append(f"SSL certificate valid for {days_left} more days")
                except Exception:
                    passed.append("SSL certificate date format not standard; manual check suggested")

        except Exception as e:
            findings.append({
                "severity": "INFO",
                "category": "SSL Certificate",
                "issue": f"Could not verify SSL certificate details: {str(e)}",
                "recommendation": "Manually verify SSL configuration"
            })

    score = max(0, score)

    if score >= 90: grade = "A"
    elif score >= 75: grade = "B"
    elif score >= 60: grade = "C"
    elif score >= 40: grade = "D"
    else: grade = "F"

    return {
        "url": url,
        "security_score": score,
        "grade": grade,
        "findings": sorted(findings, key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}.get(x["severity"], 4)),
        "passed_checks": passed,
        "total_issues": len(findings),
        "high_severity_count": len([f for f in findings if f["severity"] == "HIGH"]),
        "medium_severity_count": len([f for f in findings if f["severity"] == "MEDIUM"]),
        "low_severity_count": len([f for f in findings if f["severity"] == "LOW"]) 
    }
