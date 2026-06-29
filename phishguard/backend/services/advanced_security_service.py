import httpx
import asyncio
import ssl
import socket
import re
import base64
import urllib.parse
import dns.resolver
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from datetime import datetime
from config import settings
from services.cve_service import run_cve_scan
from services.threat_feeds_service import check_alienvault_otx, check_urlhaus
from services.compliance_service import map_to_compliance_frameworks



# ─────────────────────────────
# 1. SSL/TLS SECURITY (20%)
# ─────────────────────────────

async def check_ssl_tls(domain: str) -> dict:
    issues = []
    passed = []
    score = 100
    details = {}

    try:
        loop = asyncio.get_event_loop()

        def get_cert_details():
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    tls_version = ssock.version()
                    return cert, cipher, tls_version

        cert, cipher, tls_version = await loop.run_in_executor(None, get_cert_details)

        # Certificate validity
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_date - datetime.utcnow()).days
            details["cert_expiry_days"] = days_left
            details["cert_expiry_date"] = expire_str

            if days_left < 0:
                issues.append({"severity": "CRITICAL", "issue": "SSL certificate EXPIRED", "fix": "Renew SSL certificate immediately", "category": "SSL/TLS", "standard": "SSL/TLS Security"})
                score -= 40
            elif days_left < 14:
                issues.append({"severity": "CRITICAL", "issue": f"SSL certificate expires in {days_left} days", "fix": "Renew SSL certificate urgently", "category": "SSL/TLS", "standard": "SSL/TLS Security"})
                score -= 30
            elif days_left < 30:
                issues.append({"severity": "HIGH", "issue": f"SSL certificate expires in {days_left} days", "fix": "Renew SSL certificate soon", "category": "SSL/TLS", "standard": "SSL/TLS Security"})
                score -= 15
            else:
                passed.append(f"SSL certificate valid for {days_left} days")

        # TLS version
        details["tls_version"] = tls_version
        if tls_version == "TLSv1":
            issues.append({"severity": "CRITICAL", "issue": "TLS 1.0 in use — obsolete and insecure", "fix": "Disable TLS 1.0 and 1.1, enable only TLS 1.2 and 1.3", "category": "SSL/TLS", "standard": "SSL/TLS Security"})
            score -= 35
        elif tls_version == "TLSv1.1":
            issues.append({"severity": "HIGH", "issue": "TLS 1.1 in use — deprecated", "fix": "Disable TLS 1.1, use TLS 1.2 minimum", "category": "SSL/TLS", "standard": "SSL/TLS Security"})
            score -= 25
        elif tls_version == "TLSv1.2":
            passed.append("TLS 1.2 supported")
        elif tls_version == "TLSv1.3":
            passed.append("TLS 1.3 (latest) in use")

        # Cipher strength
        cipher_name = cipher[0] if cipher else ""
        cipher_bits = cipher[2] if cipher else 0
        details["cipher"] = cipher_name
        details["cipher_bits"] = cipher_bits

        weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "SHA1"]
        if any(w in cipher_name.upper() for w in weak_ciphers):
            issues.append({"severity": "HIGH", "issue": f"Weak cipher in use: {cipher_name}", "fix": "Configure server to use only strong ciphers (AES-256, ChaCha20)", "category": "SSL/TLS", "standard": "SSL/TLS Security"})
            score -= 20
        elif cipher_bits and cipher_bits < 128:
            issues.append({"severity": "HIGH", "issue": f"Weak cipher strength: {cipher_bits} bits", "fix": "Use minimum 128-bit cipher strength, prefer 256-bit", "category": "SSL/TLS", "standard": "SSL/TLS Security"})
            score -= 15
        else:
            passed.append(f"Strong cipher: {cipher_name} ({cipher_bits} bits)")

        # Certificate issuer
        issuer = dict(x[0] for x in cert.get("issuer", []))
        org = issuer.get("organizationName", "Unknown")
        details["cert_issuer"] = org
        if org in ["Unknown", ""]:
            issues.append({"severity": "MEDIUM", "issue": "Unknown SSL certificate issuer", "fix": "Use a certificate from a trusted CA (Let's Encrypt, DigiCert, Comodo)", "category": "SSL/TLS", "standard": "SSL/TLS Security"})
            score -= 10
        else:
            passed.append(f"Certificate issued by: {org}")

        # Subject Alternative Names
        san = cert.get("subjectAltName", [])
        details["san_count"] = len(san)
        if not san:
            issues.append({"severity": "MEDIUM", "issue": "No Subject Alternative Names (SAN) in certificate", "fix": "Use a modern certificate with SAN fields", "category": "SSL/TLS", "standard": "SSL/TLS Security"})
            score -= 8

        # SSL Grade estimation
        if score >= 90 and tls_version == "TLSv1.3":
            details["estimated_grade"] = "A+"
        elif score >= 80:
            details["estimated_grade"] = "A"
        elif score >= 65:
            details["estimated_grade"] = "B"
        elif score >= 50:
            details["estimated_grade"] = "C"
        else:
            details["estimated_grade"] = "F"

    except ssl.SSLCertVerificationError as e:
        issues.append({"severity": "CRITICAL", "issue": f"SSL verification failed: {str(e)}", "fix": "Fix SSL certificate — it may be self-signed or from untrusted CA", "category": "SSL/TLS", "standard": "SSL/TLS Security"})
        score -= 50
    except ConnectionRefusedError:
        issues.append({"severity": "CRITICAL", "issue": "No SSL/HTTPS connection available", "fix": "Enable HTTPS on your server", "category": "SSL/TLS", "standard": "SSL/TLS Security"})
        score = 0
    except Exception as e:
        issues.append({"severity": "INFO", "issue": f"SSL check error: {str(e)}", "fix": "Verify HTTPS is configured correctly", "category": "SSL/TLS", "standard": "SSL/TLS Security"})

    return {"score": max(0, score), "issues": issues, "passed": passed, "details": details}


# ─────────────────────────────
# 2. HTTP SECURITY HEADERS (20%)
# ─────────────────────────────

async def check_security_headers(url: str) -> dict:
    issues = []
    passed = []
    score = 100

    required_headers = {
        "content-security-policy": {
            "name": "Content-Security-Policy (CSP)",
            "severity": "HIGH", "deduction": 20,
            "fix": "Add CSP header: Content-Security-Policy: default-src 'self' — prevents XSS attacks",
            "explanation": "CSP prevents cross-site scripting by specifying allowed content sources"
        },
        "strict-transport-security": {
            "name": "HTTP Strict Transport Security (HSTS)",
            "severity": "HIGH", "deduction": 20,
            "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "explanation": "HSTS forces browsers to always use HTTPS"
        },
        "x-frame-options": {
            "name": "X-Frame-Options",
            "severity": "MEDIUM", "deduction": 15,
            "fix": "Add: X-Frame-Options: DENY — prevents clickjacking attacks",
            "explanation": "Prevents your site from being embedded in malicious iframes"
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options",
            "severity": "MEDIUM", "deduction": 10,
            "fix": "Add: X-Content-Type-Options: nosniff",
            "explanation": "Prevents MIME type sniffing attacks"
        },
        "referrer-policy": {
            "name": "Referrer-Policy",
            "severity": "LOW", "deduction": 8,
            "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin",
            "explanation": "Controls how much referrer info is sent with requests"
        },
        "permissions-policy": {
            "name": "Permissions-Policy",
            "severity": "LOW", "deduction": 7,
            "fix": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
            "explanation": "Restricts browser feature access"
        },
        "cross-origin-embedder-policy": {
            "name": "Cross-Origin-Embedder-Policy (COEP)",
            "severity": "LOW", "deduction": 5,
            "fix": "Add: Cross-Origin-Embedder-Policy: require-corp",
            "explanation": "Prevents cross-origin resource loading without permission"
        },
        "cross-origin-opener-policy": {
            "name": "Cross-Origin-Opener-Policy (COOP)",
            "severity": "LOW", "deduction": 5,
            "fix": "Add: Cross-Origin-Opener-Policy: same-origin",
            "explanation": "Isolates browsing context from cross-origin documents"
        }
    }

    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            r = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
            headers = dict(r.headers)

            for header_key, config in required_headers.items():
                if header_key not in headers:
                    issues.append({
                        "severity": config["severity"],
                        "issue": f"Missing {config['name']}",
                        "fix": config["fix"],
                        "explanation": config["explanation"],
                        "category": "Security Headers",
                        "standard": "HTTP Security Headers"
                    })
                    score -= config["deduction"]
                else:
                    passed.append(f"{config['name']}: present")
                    value = headers[header_key].lower()
                    if header_key == "strict-transport-security":
                        if "max-age" not in value:
                            issues.append({"severity": "MEDIUM", "issue": "HSTS missing max-age directive", "fix": "Add max-age=31536000 to HSTS header", "category": "Security Headers", "standard": "HTTP Security Headers"})
                            score -= 8
                        elif "includesubdomains" not in value:
                            issues.append({"severity": "LOW", "issue": "HSTS missing includeSubDomains directive", "fix": "Add includeSubDomains to HSTS header for full protection", "category": "Security Headers", "standard": "HTTP Security Headers"})
                            score -= 4
                    elif header_key == "x-frame-options":
                        if value not in ["deny", "sameorigin"]:
                            issues.append({"severity": "MEDIUM", "issue": f"X-Frame-Options has weak value: {value}", "fix": "Set X-Frame-Options to DENY or SAMEORIGIN", "category": "Security Headers", "standard": "HTTP Security Headers"})
                            score -= 8

            # Server version disclosure
            server = headers.get("server", "")
            if server and any(c.isdigit() for c in server):
                issues.append({"severity": "MEDIUM", "issue": f"Server header leaks version info: '{server}'", "fix": "Configure web server to hide version — reduces attack surface", "category": "Security Headers", "standard": "HTTP Security Headers"})
                score -= 8

            # X-Powered-By disclosure
            powered_by = headers.get("x-powered-by", "")
            if powered_by:
                issues.append({"severity": "MEDIUM", "issue": f"X-Powered-By reveals tech stack: '{powered_by}'", "fix": "Remove X-Powered-By header from server config", "category": "Security Headers", "standard": "HTTP Security Headers"})
                score -= 8

            # Information leakage in other headers
            leak_headers = ["x-aspnet-version", "x-aspnetmvc-version", "x-generator"]
            for lh in leak_headers:
                if lh in headers:
                    issues.append({"severity": "LOW", "issue": f"Information leak in header: {lh}: {headers[lh]}", "fix": f"Remove the {lh} header from server responses", "category": "Security Headers", "standard": "HTTP Security Headers"})
                    score -= 5

    except Exception as e:
        issues.append({"severity": "INFO", "issue": f"Header check error: {str(e)}", "fix": "Verify site is reachable", "category": "Security Headers", "standard": "HTTP Security Headers"})

    return {"score": max(0, score), "issues": issues, "passed": passed}


# ─────────────────────────────
# 3. DNS SECURITY (10%)
# ─────────────────────────────

async def check_dns_security(domain: str) -> dict:
    issues = []
    passed = []
    score = 100
    dns_records = {}

    clean_domain = domain.replace("www.", "")

    try:
        loop = asyncio.get_event_loop()

        # SPF Record
        def get_spf():
            try:
                answers = dns.resolver.resolve(clean_domain, 'TXT')
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if txt.startswith('v=spf1'):
                        return txt
            except Exception:
                return None

        spf = await loop.run_in_executor(None, get_spf)
        dns_records["spf"] = spf
        if spf:
            passed.append(f"SPF record found: {spf[:60]}")
            if "-all" in spf:
                passed.append("SPF has strict -all policy (best)")
            elif "~all" in spf:
                issues.append({"severity": "LOW", "issue": "SPF uses ~all (softfail) instead of -all (hardfail)", "fix": "Change SPF record to end with -all for strict enforcement", "category": "DNS Security", "standard": "DNS Security"})
                score -= 5
            elif "+all" in spf:
                issues.append({"severity": "HIGH", "issue": "SPF uses +all — allows ANY server to send email as your domain", "fix": "Change SPF to -all immediately to prevent email spoofing", "category": "DNS Security", "standard": "DNS Security"})
                score -= 25
        else:
            issues.append({"severity": "HIGH", "issue": "No SPF record found", "fix": "Add SPF TXT record: 'v=spf1 include:yourmailserver.com -all'", "category": "DNS Security", "standard": "DNS Security"})
            score -= 20

        # DKIM Record
        def get_dkim():
            selectors = ["default", "google", "mail", "smtp", "email", "dkim", "k1"]
            for sel in selectors:
                try:
                    answers = dns.resolver.resolve(f"{sel}._domainkey.{clean_domain}", 'TXT')
                    for rdata in answers:
                        txt = str(rdata).strip('"')
                        if "v=DKIM1" in txt or "p=" in txt:
                            return sel, txt
                except Exception:
                    continue
            return None, None

        dkim_selector, dkim_record = await loop.run_in_executor(None, get_dkim)
        dns_records["dkim"] = dkim_record
        if dkim_record:
            passed.append(f"DKIM record found (selector: {dkim_selector})")
        else:
            issues.append({"severity": "HIGH", "issue": "No DKIM record found", "fix": "Configure DKIM signing on your mail server and publish the public key as a TXT record", "category": "DNS Security", "standard": "DNS Security"})
            score -= 20

        # DMARC Record
        def get_dmarc():
            try:
                answers = dns.resolver.resolve(f"_dmarc.{clean_domain}", 'TXT')
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if txt.startswith('v=DMARC1'):
                        return txt
            except Exception:
                return None

        dmarc = await loop.run_in_executor(None, get_dmarc)
        dns_records["dmarc"] = dmarc
        if dmarc:
            passed.append("DMARC record found")
            if "p=reject" in dmarc:
                passed.append("DMARC policy: reject (strictest)")
            elif "p=quarantine" in dmarc:
                passed.append("DMARC policy: quarantine (good)")
            elif "p=none" in dmarc:
                issues.append({"severity": "MEDIUM", "issue": "DMARC policy is 'none' — no enforcement", "fix": "Change DMARC to p=quarantine or p=reject for actual protection", "category": "DNS Security", "standard": "DNS Security"})
                score -= 12
        else:
            issues.append({"severity": "HIGH", "issue": "No DMARC record found", "fix": "Add DMARC TXT record: '_dmarc.yourdomain.com' with 'v=DMARC1; p=quarantine; rua=mailto:admin@yourdomain.com'", "category": "DNS Security", "standard": "DNS Security"})
            score -= 20

        # DNSSEC
        def get_dnssec():
            try:
                answers = dns.resolver.resolve(clean_domain, 'DNSKEY')
                return len(answers) > 0
            except Exception:
                return False

        has_dnssec = await loop.run_in_executor(None, get_dnssec)
        dns_records["dnssec"] = has_dnssec
        if has_dnssec:
            passed.append("DNSSEC enabled — DNS responses are cryptographically signed")
        else:
            issues.append({"severity": "MEDIUM", "issue": "DNSSEC not enabled", "fix": "Enable DNSSEC through your domain registrar to prevent DNS spoofing", "category": "DNS Security", "standard": "DNS Security"})
            score -= 15

        # MX Records
        def get_mx():
            try:
                return [str(r.exchange) for r in dns.resolver.resolve(clean_domain, 'MX')]
            except Exception:
                return []

        mx_records = await loop.run_in_executor(None, get_mx)
        dns_records["mx"] = mx_records
        if mx_records:
            passed.append(f"MX records found: {', '.join(mx_records[:2])}")
        else:
            issues.append({"severity": "LOW", "issue": "No MX records found", "fix": "Add MX records if you need to receive email for this domain", "category": "DNS Security", "standard": "DNS Security"})
            score -= 5

        # CAA Records
        def get_caa():
            try:
                answers = dns.resolver.resolve(clean_domain, 'CAA')
                return [str(r) for r in answers]
            except Exception:
                return []

        caa_records = await loop.run_in_executor(None, get_caa)
        dns_records["caa"] = caa_records
        if caa_records:
            passed.append("CAA records present — restricts SSL certificate issuance")
        else:
            issues.append({"severity": "LOW", "issue": "No CAA (Certificate Authority Authorization) records", "fix": "Add CAA records to specify which CAs can issue certificates for your domain", "category": "DNS Security", "standard": "DNS Security"})
            score -= 5

    except Exception as e:
        issues.append({"severity": "INFO", "issue": f"DNS check error: {str(e)}", "fix": "Verify DNS configuration", "category": "DNS Security", "standard": "DNS Security"})

    return {"score": max(0, score), "issues": issues, "passed": passed, "dns_records": dns_records}


# ─────────────────────────────
# 4. DOMAIN REPUTATION (15%)
# ─────────────────────────────

async def check_domain_reputation(url: str, domain: str) -> dict:
    issues = []
    passed = []
    score = 100
    details = {}

    clean_domain = domain.replace("www.", "")

    async with httpx.AsyncClient(timeout=15) as client:

        # WHOIS / Domain age
        try:
            whois_r = await client.get(
                f"https://api.whoisfreaks.com/v1.0/whois?whois=live&domainName={clean_domain}&apiKey=free",
                timeout=8
            )
            if whois_r.status_code == 200:
                data = whois_r.json()
                created = data.get("create_date", "")
                if created:
                    try:
                        created_date = datetime.strptime(created[:10], "%Y-%m-%d")
                        age_days = (datetime.utcnow() - created_date).days
                        details["domain_age_days"] = age_days
                        details["domain_created"] = created[:10]
                        if age_days < 30:
                            issues.append({"severity": "CRITICAL", "issue": f"Domain is only {age_days} days old — very new", "fix": "New domains are high-risk — verify legitimacy before trusting", "category": "Domain Reputation", "standard": "Domain & Reputation"})
                            score -= 40
                        elif age_days < 90:
                            issues.append({"severity": "HIGH", "issue": f"Domain registered {age_days} days ago", "fix": "Relatively new domain — proceed with caution", "category": "Domain Reputation", "standard": "Domain & Reputation"})
                            score -= 20
                        elif age_days < 365:
                            issues.append({"severity": "MEDIUM", "issue": f"Domain is less than 1 year old ({age_days} days)", "fix": "Domain trust increases with age", "category": "Domain Reputation", "standard": "Domain & Reputation"})
                            score -= 10
                        else:
                            passed.append(f"Established domain: {round(age_days/365, 1)} years old")
                        registrar = data.get("registrar_name", "")
                        if registrar:
                            details["registrar"] = registrar
                            passed.append(f"Registrar: {registrar}")
                    except Exception:
                        pass
        except Exception:
            pass

        # VirusTotal domain reputation
        if settings.VIRUSTOTAL_API_KEY:
            try:
                vt_r = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{clean_domain}",
                    headers={"x-apikey": settings.VIRUSTOTAL_API_KEY}
                )
                if vt_r.status_code == 200:
                    vt_data = vt_r.json()
                    attrs = vt_data.get("data", {}).get("attributes", {})
                    reputation = attrs.get("reputation", 0)
                    stats = attrs.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    details["vt_reputation"] = reputation
                    details["vt_malicious"] = malicious
                    if malicious > 0:
                        issues.append({"severity": "CRITICAL", "issue": f"VirusTotal: {malicious} engines flagged this domain as malicious", "fix": "Domain has active malware/phishing detections — avoid", "category": "Domain Reputation", "standard": "Domain & Reputation"})
                        score -= 40
                    elif reputation < -10:
                        issues.append({"severity": "HIGH", "issue": f"Poor VirusTotal reputation score: {reputation}", "fix": "Domain has negative reputation history", "category": "Domain Reputation", "standard": "Domain & Reputation"})
                        score -= 20
                    else:
                        passed.append(f"VirusTotal reputation: {reputation} (clean)")
            except Exception:
                pass

        # PhishTank check
        try:
            pt_r = await client.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={"url": url, "format": "json"},
                headers={"User-Agent": "CyberLens/1.0"},
                timeout=8
            )
            if pt_r.status_code == 200:
                pt_data = pt_r.json()
                in_db = pt_data.get("results", {}).get("in_database", False)
                verified = pt_data.get("results", {}).get("verified", False)
                details["phishtank"] = {"in_database": in_db, "verified": verified}
                if verified:
                    issues.append({"severity": "CRITICAL", "issue": "VERIFIED phishing URL in PhishTank database", "fix": "This URL is a confirmed phishing site — do not visit", "category": "Domain Reputation", "standard": "Domain & Reputation"})
                    score -= 50
                elif in_db:
                    issues.append({"severity": "HIGH", "issue": "URL reported in PhishTank database", "fix": "URL has been reported as phishing", "category": "Domain Reputation", "standard": "Domain & Reputation"})
                    score -= 30
                else:
                    passed.append("PhishTank: Not in phishing database")
        except Exception:
            pass

        # Certificate Transparency via crt.sh
        try:
            crt_r = await client.get(
                f"https://crt.sh/?q=%.{clean_domain}&output=json",
                timeout=10
            )
            if crt_r.status_code == 200:
                certs = crt_r.json()
                subdomains = set()
                for entry in certs:
                    for sub in entry.get("name_value", "").split("\n"):
                        sub = sub.strip().lower()
                        if sub and "*" not in sub:
                            subdomains.add(sub)
                details["subdomains_found"] = len(subdomains)
                details["total_certs"] = len(certs)
                passed.append(f"Certificate Transparency: {len(certs)} certs, {len(subdomains)} subdomains found")
        except Exception:
            pass

    return {"score": max(0, score), "issues": issues, "passed": passed, "details": details}


# ─────────────────────────────
# 5. VULNERABILITY ASSESSMENT (20%)
# ─────────────────────────────

async def check_vulnerabilities(url: str) -> dict:
    issues = []
    passed = []
    score = 100

    try:
        async with httpx.AsyncClient(
            timeout=15, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"}
        ) as client:
            r = await client.get(url)
            soup = BeautifulSoup(r.text, "html.parser")
            content = r.text
            content_lower = content.lower()
            headers = dict(r.headers)

            # XSS Indicators
            dangerous_js = ["document.write(", "innerHTML =", "eval(", ".html("]
            xss_indicators = [p for p in dangerous_js if p in content]

            inline_scripts = soup.find_all("script", src=False)
            if len(inline_scripts) > 5:
                issues.append({"severity": "MEDIUM", "issue": f"{len(inline_scripts)} inline script blocks found (XSS risk)", "fix": "Move inline scripts to external files and use CSP to block inline scripts", "category": "Vulnerability", "standard": "OWASP — Injection", "owasp": "A03:2021 Injection"})
                score -= 10

            if xss_indicators:
                issues.append({"severity": "HIGH", "issue": f"Potentially dangerous JavaScript patterns: {', '.join(xss_indicators[:3])}", "fix": "Audit these JavaScript patterns — document.write and innerHTML can enable XSS if user input is involved", "category": "Vulnerability", "standard": "OWASP — Injection", "owasp": "A03:2021 Injection"})
                score -= 15

            # SQL Injection Indicators
            sql_error_patterns = [
                "you have an error in your sql syntax", "warning: mysql",
                "unclosed quotation mark", "microsoft ole db provider for sql server",
                "odbc sql server driver", "ora-01756",
                "mysql_fetch_array()", "pg_exec()"
            ]
            sql_errors_found = [p for p in sql_error_patterns if p in content_lower]
            if sql_errors_found:
                issues.append({"severity": "CRITICAL", "issue": f"SQL error messages exposed: '{sql_errors_found[0]}'", "fix": "CRITICAL: Disable detailed error messages in production. Use parameterized queries.", "category": "Vulnerability", "standard": "OWASP — Injection", "owasp": "A03:2021 Injection"})
                score -= 40

            # CSRF Protection
            forms = soup.find_all("form", method=lambda m: m and m.lower() == "post")
            csrf_missing = 0
            for form in forms:
                csrf = form.find("input", attrs={"name": re.compile(r'csrf|token|_token|nonce', re.I)})
                if not csrf:
                    csrf_missing += 1
            if csrf_missing > 0:
                issues.append({"severity": "HIGH", "issue": f"{csrf_missing} POST form(s) appear to lack CSRF protection", "fix": "Add CSRF tokens to all POST forms to prevent cross-site request forgery attacks", "category": "Vulnerability", "standard": "OWASP — CSRF", "owasp": "A01:2021 Broken Access Control"})
                score -= 20
            elif forms:
                passed.append("CSRF token found in POST forms")

            # Open Redirect Indicators
            open_redirect_params = ["redirect", "url", "next", "return", "returnto", "goto", "forward"]
            links = soup.find_all("a", href=True)
            redirect_concerns = []
            for link in links:
                href = link.get("href", "")
                for param in open_redirect_params:
                    if f"?{param}=" in href or f"&{param}=" in href:
                        redirect_concerns.append(href[:80])
                        break
            if redirect_concerns:
                issues.append({"severity": "HIGH", "issue": f"{len(redirect_concerns)} potential open redirect parameter(s) found", "fix": "Validate and whitelist allowed redirect destinations — open redirects enable phishing", "category": "Vulnerability", "standard": "OWASP — Insecure Design", "owasp": "A04:2021 Insecure Design"})
                score -= 15

            # Clickjacking
            if "x-frame-options" not in headers and "content-security-policy" not in headers:
                issues.append({"severity": "HIGH", "issue": "No clickjacking protection (no X-Frame-Options or CSP frame-ancestors)", "fix": "Add X-Frame-Options: DENY or CSP frame-ancestors 'none' to prevent clickjacking", "category": "Vulnerability", "standard": "OWASP — Clickjacking", "owasp": "A05:2021 Security Misconfiguration"})
                score -= 18

            # Directory Listing
            dir_listing_found = False
            for dir_path in ["/images/", "/uploads/", "/assets/", "/files/"]:
                try:
                    dr = await client.get(url.rstrip("/") + dir_path, timeout=5, follow_redirects=False)
                    if dr.status_code == 200:
                        dr_lower = dr.text.lower()
                        if "index of /" in dr_lower or "directory listing" in dr_lower:
                            dir_listing_found = True
                            break
                except Exception:
                    pass
            if dir_listing_found:
                issues.append({"severity": "HIGH", "issue": "Directory listing enabled — file structure exposed", "fix": "Disable directory listing in web server config (Options -Indexes in Apache)", "category": "Vulnerability", "standard": "OWASP — Security Misconfiguration", "owasp": "A05:2021 Security Misconfiguration"})
                score -= 20
            else:
                passed.append("Directory listing disabled")

            # Sensitive File Exposure
            sensitive_paths = [
                ("/.env", "CRITICAL", "Environment file exposed"),
                ("/.git/config", "CRITICAL", "Git config exposed"),
                ("/wp-config.php", "CRITICAL", "WordPress config exposed"),
                ("/config.php", "CRITICAL", "Config file exposed"),
                ("/phpinfo.php", "HIGH", "PHP info exposed"),
                ("/.htpasswd", "CRITICAL", "Password file exposed"),
                ("/backup.zip", "CRITICAL", "Backup exposed"),
                ("/admin/", "HIGH", "Admin panel accessible"),
                ("/server-status", "MEDIUM", "Server status page exposed"),
            ]
            for path, severity, desc in sensitive_paths:
                try:
                    sr = await client.get(url.rstrip("/") + path, timeout=5, follow_redirects=False)
                    if sr.status_code == 200:
                        issues.append({"severity": severity, "issue": f"{desc}: {path}", "fix": f"Block access to {path} immediately", "category": "Vulnerability", "standard": "OWASP — Security Misconfiguration", "owasp": "A05:2021 Security Misconfiguration"})
                        score -= 30 if severity == "CRITICAL" else 20
                except Exception:
                    pass

            # Insecure Form Submission
            if urlparse(url).scheme == "http":
                password_fields = soup.find_all("input", {"type": "password"})
                if password_fields:
                    issues.append({"severity": "CRITICAL", "issue": "Password form over HTTP — credentials sent in plain text", "fix": "CRITICAL: Move to HTTPS immediately", "category": "Vulnerability", "standard": "OWASP — Cryptographic Failures", "owasp": "A02:2021 Cryptographic Failures"})
                    score -= 40

            # Mixed Content
            if urlparse(url).scheme == "https":
                http_srcs = re.findall(r'src=["\']http://[^"\']+["\']', content)
                if http_srcs:
                    issues.append({"severity": "HIGH", "issue": f"Mixed content: {len(http_srcs)} resource(s) loaded over HTTP", "fix": "Update all resource URLs to HTTPS", "category": "Vulnerability", "standard": "OWASP — Cryptographic Failures", "owasp": "A02:2021 Cryptographic Failures"})
                    score -= 15

            # Outdated Library Detection
            outdated_patterns = {
                "jquery/1.": "jQuery 1.x (outdated, known vulnerabilities)",
                "jquery/2.": "jQuery 2.x (outdated)",
                "bootstrap/3.": "Bootstrap 3.x (outdated)",
                "angular.js": "AngularJS (End of Life)",
            }
            for pattern, desc in outdated_patterns.items():
                if pattern in content_lower:
                    issues.append({"severity": "MEDIUM", "issue": f"Outdated library: {desc}", "fix": "Update to latest version — older libraries have known vulnerabilities", "category": "Vulnerability", "standard": "OWASP — Vulnerable Components", "owasp": "A06:2021 Vulnerable and Outdated Components"})
                    score -= 10

            # HTML Comment Exposure
            html_comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
            sensitive_kw = ["password", "api_key", "secret", "token", "credentials", "database"]
            for comment in html_comments:
                cl = comment.lower()
                for kw in sensitive_kw:
                    if kw in cl:
                        issues.append({"severity": "HIGH", "issue": f"Sensitive info in HTML comment (contains '{kw}')", "fix": "Remove all sensitive information from HTML comments", "category": "Vulnerability", "standard": "OWASP — Security Misconfiguration", "owasp": "A05:2021 Security Misconfiguration"})
                        score -= 20
                        break

            if not issues:
                passed.append("No obvious vulnerabilities detected in page source")

    except Exception as e:
        issues.append({"severity": "INFO", "issue": f"Vulnerability check error: {str(e)}", "fix": "Verify site is reachable", "category": "Vulnerability", "standard": "Vulnerability Assessment"})

    return {"score": max(0, score), "issues": issues, "passed": passed}


# ─────────────────────────────
# 6. THREAT INTELLIGENCE (10%)
# ─────────────────────────────

async def check_threat_intelligence(url: str, domain: str) -> dict:
    issues = []
    passed = []
    score = 100
    details = {}

    clean_domain = domain.replace("www.", "")

    async with httpx.AsyncClient(timeout=15) as client:

        # VirusTotal URL scan
        if settings.VIRUSTOTAL_API_KEY:
            try:
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                vt_r = await client.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers={"x-apikey": settings.VIRUSTOTAL_API_KEY}
                )
                if vt_r.status_code == 200:
                    data = vt_r.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values())
                    details["vt_malicious"] = malicious
                    details["vt_total_engines"] = total
                    if malicious > 0:
                        issues.append({"severity": "CRITICAL", "issue": f"VirusTotal: {malicious}/{total} engines flagged URL as malicious", "fix": "URL is flagged by multiple security vendors", "category": "Threat Intelligence", "standard": "Threat Intelligence"})
                        score -= 40
                    else:
                        passed.append(f"VirusTotal: Clean ({total} engines checked)")
            except Exception:
                pass

        # Google Safe Browsing
        if settings.SAFE_BROWSING_API_KEY:
            try:
                sb_r = await client.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.SAFE_BROWSING_API_KEY}",
                    json={
                        "client": {"clientId": "cyberlens", "clientVersion": "1.0"},
                        "threatInfo": {
                            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                            "platformTypes": ["ANY_PLATFORM"],
                            "threatEntryTypes": ["URL"],
                            "threatEntries": [{"url": url}]
                        }
                    }
                )
                if sb_r.status_code == 200:
                    matches = sb_r.json().get("matches", [])
                    if matches:
                        threat_types = list(set([m["threatType"] for m in matches]))
                        issues.append({"severity": "CRITICAL", "issue": f"Google Safe Browsing flagged: {', '.join(threat_types)}", "fix": "URL is in Google's threat database — do not visit", "category": "Threat Intelligence", "standard": "Threat Intelligence"})
                        score -= 50
                    else:
                        passed.append("Google Safe Browsing: Clean")
            except Exception:
                pass

        # IPQualityScore
        if settings.IPQS_API_KEY:
            try:
                encoded = urllib.parse.quote(url, safe='')
                ipqs_r = await client.get(
                    f"https://www.ipqualityscore.com/api/json/url/{settings.IPQS_API_KEY}/{encoded}"
                )
                if ipqs_r.status_code == 200:
                    ipqs_data = ipqs_r.json()
                    risk_score = ipqs_data.get("risk_score", 0)
                    details["ipqs_risk"] = risk_score
                    if ipqs_data.get("phishing"):
                        issues.append({"severity": "CRITICAL", "issue": "IPQualityScore confirmed phishing URL", "fix": "URL identified as phishing by ML model", "category": "Threat Intelligence", "standard": "Threat Intelligence"})
                        score -= 40
                    elif risk_score > 75:
                        issues.append({"severity": "HIGH", "issue": f"IPQualityScore high risk: {risk_score}/100", "fix": "URL has high fraud risk score", "category": "Threat Intelligence", "standard": "Threat Intelligence"})
                        score -= 20
                    else:
                        passed.append(f"IPQualityScore: Risk {risk_score}/100")
            except Exception:
                pass

    return {"score": max(0, score), "issues": issues, "passed": passed, "details": details}


# ─────────────────────────────
# 7. COOKIE SECURITY (5%)
# ─────────────────────────────

async def check_cookie_security(url: str) -> dict:
    issues = []
    passed = []
    score = 100

    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            r = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})

            # Collect all Set-Cookie headers
            all_cookies = []
            for key, value in r.headers.multi_items():
                if key.lower() == "set-cookie":
                    all_cookies.append(value)

            if not all_cookies:
                passed.append("No cookies set on this page")
                return {"score": score, "issues": issues, "passed": passed}

            for cookie in all_cookies:
                cookie_lower = cookie.lower()
                cookie_name = cookie.split("=")[0].strip()

                if "secure" not in cookie_lower:
                    issues.append({"severity": "HIGH", "issue": f"Cookie '{cookie_name}' missing Secure flag", "fix": f"Add Secure flag to cookie '{cookie_name}' — prevents transmission over HTTP", "category": "Cookie Security", "standard": "Cookie Security"})
                    score -= 15
                else:
                    passed.append(f"Cookie '{cookie_name}': Secure flag present")

                if "httponly" not in cookie_lower:
                    issues.append({"severity": "HIGH", "issue": f"Cookie '{cookie_name}' missing HttpOnly flag", "fix": f"Add HttpOnly flag to prevent JavaScript access to cookie '{cookie_name}'", "category": "Cookie Security", "standard": "Cookie Security"})
                    score -= 15
                else:
                    passed.append(f"Cookie '{cookie_name}': HttpOnly flag present")

                if "samesite" not in cookie_lower:
                    issues.append({"severity": "MEDIUM", "issue": f"Cookie '{cookie_name}' missing SameSite attribute", "fix": f"Add SameSite=Strict or SameSite=Lax to cookie '{cookie_name}' to prevent CSRF", "category": "Cookie Security", "standard": "Cookie Security"})
                    score -= 10
                elif "samesite=none" in cookie_lower and "secure" not in cookie_lower:
                    issues.append({"severity": "HIGH", "issue": f"Cookie '{cookie_name}' has SameSite=None without Secure", "fix": "SameSite=None requires Secure flag — add Secure attribute", "category": "Cookie Security", "standard": "Cookie Security"})
                    score -= 15

                if "max-age" not in cookie_lower and "expires" not in cookie_lower:
                    issues.append({"severity": "LOW", "issue": f"Cookie '{cookie_name}' has no expiration (session cookie)", "fix": "Set Max-Age or Expires for persistent cookies to limit lifetime", "category": "Cookie Security", "standard": "Cookie Security"})
                    score -= 5

                # Check for __Secure- / __Host- prefix
                if cookie_name.startswith("__Secure-") and "secure" not in cookie_lower:
                    issues.append({"severity": "HIGH", "issue": f"Cookie '{cookie_name}' uses __Secure- prefix without Secure flag", "fix": "Cookies with __Secure- prefix MUST have Secure flag", "category": "Cookie Security", "standard": "Cookie Security"})
                    score -= 15

    except Exception as e:
        issues.append({"severity": "INFO", "issue": f"Cookie check error: {str(e)}", "fix": "Verify site is reachable", "category": "Cookie Security", "standard": "Cookie Security"})

    return {"score": max(0, score), "issues": issues, "passed": passed}


# ═══════════════════════════════
# OWASP COMPLIANCE HELPER
# ═══════════════════════════════

def generate_owasp_summary(vuln_result: dict) -> dict:
    owasp_categories = {
        "A01:2021-Broken Access Control": {"name": "Broken Access Control", "status": "COMPLIANT", "findings": []},
        "A02:2021-Cryptographic Failures": {"name": "Cryptographic Failures", "status": "COMPLIANT", "findings": []},
        "A03:2021-Injection": {"name": "Injection", "status": "COMPLIANT", "findings": []},
        "A04:2021-Insecure Design": {"name": "Insecure Design", "status": "COMPLIANT", "findings": []},
        "A05:2021-Security Misconfiguration": {"name": "Security Misconfiguration", "status": "COMPLIANT", "findings": []},
        "A06:2021-Vulnerable and Outdated Components": {"name": "Vulnerable and Outdated Components", "status": "COMPLIANT", "findings": []},
        "A07:2021-Identification and Authentication Failures": {"name": "Identification and Authentication Failures", "status": "COMPLIANT", "findings": []},
        "A08:2021-Software and Data Integrity Failures": {"name": "Software and Data Integrity Failures", "status": "COMPLIANT", "findings": []},
        "A09:2021-Security Logging and Monitoring Failures": {"name": "Security Logging and Monitoring Failures", "status": "COMPLIANT", "findings": []},
        "A10:2021-Server-Side Request Forgery": {"name": "Server-Side Request Forgery (SSRF)", "status": "COMPLIANT", "findings": []}
    }

    issues = vuln_result.get("issues", [])
    for issue in issues:
        owasp_tag = issue.get("owasp", "")
        if not owasp_tag:
            continue
        
        for key in owasp_categories.keys():
            short_code = key.split(":")[0]
            if short_code in owasp_tag:
                owasp_categories[key]["findings"].append(issue.get("issue", ""))
                owasp_categories[key]["status"] = "NON-COMPLIANT"

    return {
        "categories": owasp_categories,
        "compliant_count": sum(1 for c in owasp_categories.values() if c["status"] == "COMPLIANT"),
        "non_compliant_count": sum(1 for c in owasp_categories.values() if c["status"] == "NON-COMPLIANT")
    }

# ═══════════════════════════════
# MASTER SECURITY AUDIT RUNNER
# ═══════════════════════════════

async def run_advanced_security_audit(url: str) -> dict:
    domain = urlparse(url).netloc
    clean_domain = domain.replace("www.", "")

    # Run all checks in parallel including new ones
    results = await asyncio.gather(
        check_ssl_tls(clean_domain),
        check_security_headers(url),
        check_dns_security(clean_domain),
        check_domain_reputation(url, clean_domain),
        check_vulnerabilities(url),
        check_threat_intelligence(url, clean_domain),
        check_cookie_security(url),
        run_cve_scan(url),
        check_alienvault_otx(clean_domain, url),
        check_urlhaus(url),
        return_exceptions=True
    )

    ssl_result = results[0] if not isinstance(results[0], Exception) else {"score": 0, "issues": [], "passed": [], "details": {}}
    headers_result = results[1] if not isinstance(results[1], Exception) else {"score": 0, "issues": [], "passed": []}
    dns_result = results[2] if not isinstance(results[2], Exception) else {"score": 0, "issues": [], "passed": [], "dns_records": {}}
    reputation_result = results[3] if not isinstance(results[3], Exception) else {"score": 0, "issues": [], "passed": [], "details": {}}
    vuln_result = results[4] if not isinstance(results[4], Exception) else {"score": 0, "issues": [], "passed": []}
    threat_result = results[5] if not isinstance(results[5], Exception) else {"score": 0, "issues": [], "passed": [], "details": {}}
    cookie_result = results[6] if not isinstance(results[6], Exception) else {"score": 0, "issues": [], "passed": []}
    cve_result = results[7] if not isinstance(results[7], Exception) else {"score": 0, "issues": [], "passed": [], "technologies": [], "cves": []}
    otx_result = results[8] if not isinstance(results[8], Exception) else {"score": 100, "issues": [], "passed": []}
    urlhaus_result = results[9] if not isinstance(results[9], Exception) else {"score": 100, "issues": [], "passed": []}

    # Merge OTX + URLHaus into threat intelligence
    threat_result["issues"] = threat_result.get("issues", []) + \
        otx_result.get("issues", []) + \
        urlhaus_result.get("issues", [])
    threat_result["passed"] = threat_result.get("passed", []) + \
        otx_result.get("passed", []) + \
        urlhaus_result.get("passed", [])
    threat_result["score"] = round(
        threat_result.get("score", 100) * 0.4 +
        otx_result.get("score", 100) * 0.3 +
        urlhaus_result.get("score", 100) * 0.3
    )

    # Weighted security score
    security_score = round(
        ssl_result["score"] * 0.20 +
        headers_result["score"] * 0.20 +
        dns_result["score"] * 0.10 +
        reputation_result["score"] * 0.15 +
        vuln_result["score"] * 0.15 +
        threat_result["score"] * 0.10 +
        cookie_result["score"] * 0.05 +
        cve_result["score"] * 0.05
    )

    # Combine all issues
    all_issues = (
        ssl_result.get("issues", []) +
        headers_result.get("issues", []) +
        dns_result.get("issues", []) +
        reputation_result.get("issues", []) +
        vuln_result.get("issues", []) +
        threat_result.get("issues", []) +
        cookie_result.get("issues", []) +
        cve_result.get("issues", [])
    )

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_issues.sort(key=lambda x: severity_order.get(x.get("severity", "INFO"), 5))

    # OWASP compliance
    owasp_summary = generate_owasp_summary(vuln_result)

    # Compliance framework mapping
    compliance_mapping = map_to_compliance_frameworks(all_issues)

    if security_score >= 90: grade = "A+"
    elif security_score >= 80: grade = "A"
    elif security_score >= 70: grade = "B"
    elif security_score >= 60: grade = "C"
    elif security_score >= 40: grade = "D"
    else: grade = "F"

    # Compatibility list of passed items
    all_passed = (
        ssl_result.get("passed", []) +
        headers_result.get("passed", []) +
        dns_result.get("passed", []) +
        reputation_result.get("passed", []) +
        vuln_result.get("passed", []) +
        threat_result.get("passed", []) +
        cookie_result.get("passed", []) +
        cve_result.get("passed", [])
    )

    return {
        "url": url,
        "security_score": security_score,
        "overall_score": security_score,  # Compatibility key
        "grade": grade,
        "critical_count": len([i for i in all_issues if i["severity"] == "CRITICAL"]),
        "critical_issues": len([i for i in all_issues if i["severity"] == "CRITICAL"]),  # Compatibility key
        "high_count": len([i for i in all_issues if i["severity"] == "HIGH"]),
        "high_issues": len([i for i in all_issues if i["severity"] == "HIGH"]),  # Compatibility key
        "medium_count": len([i for i in all_issues if i["severity"] == "MEDIUM"]),
        "medium_issues": len([i for i in all_issues if i["severity"] == "MEDIUM"]),  # Compatibility key
        "low_count": len([i for i in all_issues if i["severity"] == "LOW"]),
        "low_issues": len([i for i in all_issues if i["severity"] == "LOW"]),  # Compatibility key
        "total_issues": len(all_issues),
        "all_issues": all_issues,
        "all_passed": all_passed,
        "ssl_tls": ssl_result,
        "security_headers": headers_result,
        "dns_security": dns_result,
        "domain_reputation": reputation_result,
        "vulnerability_assessment": vuln_result,
        "threat_intelligence": {
            **threat_result,
            "otx": otx_result,
            "urlhaus": urlhaus_result
        },
        "cookie_security": cookie_result,
        "cve_analysis": cve_result,
        "owasp_compliance": owasp_summary,
        "compliance_mapping": compliance_mapping,
        "categories": {
            "ssl_tls":    {"label": "SSL/TLS Security",       "weight": 0.20, "score": ssl_result["score"],    "issues": ssl_result.get("issues", []),    "passed": ssl_result.get("passed", []),    "details": ssl_result.get("details", {})},
            "headers":    {"label": "Security Headers",       "weight": 0.20, "score": headers_result["score"], "issues": headers_result.get("issues", []), "passed": headers_result.get("passed", [])},
            "dns":        {"label": "DNS Security",           "weight": 0.10, "score": dns_result["score"],    "issues": dns_result.get("issues", []),    "passed": dns_result.get("passed", []),    "dns_records": dns_result.get("dns_records", {})},
            "reputation": {"label": "Domain Reputation",      "weight": 0.15, "score": reputation_result["score"], "issues": reputation_result.get("issues", []), "passed": reputation_result.get("passed", []), "details": reputation_result.get("details", {})},
            "vulns":      {"label": "Vulnerability Assessment","weight": 0.15, "score": vuln_result["score"],      "issues": vuln_result.get("issues", []),      "passed": vuln_result.get("passed", [])},
            "threat":     {"label": "Threat Intelligence",    "weight": 0.10, "score": threat_result["score"], "issues": threat_result.get("issues", []), "passed": threat_result.get("passed", []), "details": threat_result.get("details", {})},
            "cookies":    {"label": "Cookie Security",        "weight": 0.05, "score": cookie_result["score"],    "issues": cookie_result.get("issues", []),    "passed": cookie_result.get("passed", [])},
            "cve_analysis": {"label": "CVE Analysis",          "weight": 0.05, "score": cve_result["score"],        "issues": cve_result.get("issues", []),        "passed": cve_result.get("passed", []),        "details": cve_result.get("technologies", [])}
        },
        "score_breakdown": {
            "ssl_tls": {"score": ssl_result["score"], "weight": "20%"},
            "security_headers": {"score": headers_result["score"], "weight": "20%"},
            "dns_security": {"score": dns_result["score"], "weight": "10%"},
            "domain_reputation": {"score": reputation_result["score"], "weight": "15%"},
            "vulnerability_assessment": {"score": vuln_result["score"], "weight": "15%"},
            "threat_intelligence": {"score": threat_result["score"], "weight": "10%"},
            "cookie_security": {"score": cookie_result["score"], "weight": "5%"},
            "cve_analysis": {"score": cve_result["score"], "weight": "5%"}
        },
        "timestamp": __import__('datetime').datetime.utcnow().isoformat()
    }
