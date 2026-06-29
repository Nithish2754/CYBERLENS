import httpx
import asyncio
import ssl
import socket
import re
import time
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from datetime import datetime

# ─────────────────────────────
# 1. SECURITY CHECK (40% weight)
# ─────────────────────────────

async def check_security(url: str, domain: str) -> dict:
    issues = []
    passed = []
    score = 100

    try:
        async with httpx.AsyncClient(
            timeout=15, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"}
        ) as client:
            r = await client.get(url)
            headers = dict(r.headers)
            content = r.text

            # HTTPS/SSL
            if urlparse(url).scheme == "http":
                issues.append({"severity": "CRITICAL", "issue": "Site does not use HTTPS", "fix": "Get a free SSL certificate via Let's Encrypt and redirect all HTTP to HTTPS", "category": "Security"})
                score -= 25
            else:
                passed.append("HTTPS enabled")

            # Security Headers
            security_headers = {
                "strict-transport-security": ("HSTS header missing", "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains", "HIGH", 12),
                "content-security-policy": ("Content-Security-Policy (CSP) header missing", "Add CSP header to prevent XSS: Content-Security-Policy: default-src 'self'", "HIGH", 10),
                "x-frame-options": ("X-Frame-Options header missing", "Add: X-Frame-Options: DENY to prevent clickjacking", "MEDIUM", 8),
                "x-content-type-options": ("X-Content-Type-Options header missing", "Add: X-Content-Type-Options: nosniff", "MEDIUM", 5),
                "referrer-policy": ("Referrer-Policy header missing", "Add: Referrer-Policy: strict-origin-when-cross-origin", "LOW", 4),
                "permissions-policy": ("Permissions-Policy header missing", "Add Permissions-Policy to restrict browser features", "LOW", 3),
            }
            for header, (issue_text, fix_text, severity, deduction) in security_headers.items():
                if header not in headers:
                    issues.append({"severity": severity, "issue": issue_text, "fix": fix_text, "category": "Security"})
                    score -= deduction
                else:
                    passed.append(f"{header} present")

            # Server version disclosure
            server = headers.get("server", "")
            if server and any(c.isdigit() for c in server):
                issues.append({"severity": "LOW", "issue": f"Server header reveals version: '{server}'", "fix": "Hide the Server header in your web server config", "category": "Security"})
                score -= 5

            # X-Powered-By disclosure
            powered_by = headers.get("x-powered-by", "")
            if powered_by:
                issues.append({"severity": "LOW", "issue": f"X-Powered-By reveals technology: '{powered_by}'", "fix": "Remove X-Powered-By header to hide tech stack", "category": "Security"})
                score -= 4

            # Mixed content
            if urlparse(url).scheme == "https":
                http_resources = re.findall(r'src=["\']http://[^"\']+["\']', content)
                if http_resources:
                    issues.append({"severity": "HIGH", "issue": f"Mixed content: {len(http_resources)} resource(s) loaded over HTTP on HTTPS page", "fix": "Update all resource URLs to HTTPS", "category": "Security"})
                    score -= 15

            # Cookie security
            set_cookie = headers.get("set-cookie", "")
            if set_cookie:
                if "secure" not in set_cookie.lower():
                    issues.append({"severity": "MEDIUM", "issue": "Cookie missing Secure flag", "fix": "Add Secure flag to all cookies", "category": "Security"})
                    score -= 6
                if "httponly" not in set_cookie.lower():
                    issues.append({"severity": "MEDIUM", "issue": "Cookie missing HttpOnly flag", "fix": "Add HttpOnly flag to prevent JS access to cookies", "category": "Security"})
                    score -= 6
                if "samesite" not in set_cookie.lower():
                    issues.append({"severity": "LOW", "issue": "Cookie missing SameSite attribute", "fix": "Add SameSite=Strict to cookies to prevent CSRF", "category": "Security"})
                    score -= 3
                else:
                    passed.append("Cookie security flags present")

            # XSS detection (basic — check for unescaped inputs)
            soup = BeautifulSoup(content, "html.parser")
            forms = soup.find_all("form")
            for form in forms:
                inputs = form.find_all("input")
                for inp in inputs:
                    if inp.get("type") not in ["hidden", "submit", "button"]:
                        if not inp.get("maxlength") and not inp.get("pattern"):
                            issues.append({"severity": "MEDIUM", "issue": "Form input missing validation attributes (possible XSS vector)", "fix": "Add maxlength, pattern, and server-side validation to all form inputs", "category": "Security"})
                            score -= 5
                            break

            # CSRF token check on forms
            for form in forms:
                method = form.get("method", "get").lower()
                if method == "post":
                    csrf_input = form.find("input", attrs={"name": re.compile(r'csrf|token|_token', re.I)})
                    if not csrf_input:
                        issues.append({"severity": "HIGH", "issue": "POST form may be missing CSRF protection token", "fix": "Add CSRF tokens to all POST forms to prevent cross-site request forgery", "category": "Security"})
                        score -= 8

            # Exposed sensitive paths
            sensitive_paths = [
                ("/.env", "CRITICAL", "Environment file with credentials exposed"),
                ("/.git/config", "CRITICAL", "Git repository exposed"),
                ("/wp-admin", "HIGH", "WordPress admin panel exposed"),
                ("/admin", "HIGH", "Admin panel exposed"),
                ("/phpinfo.php", "HIGH", "PHP info page exposed"),
                ("/.htaccess", "MEDIUM", "Apache config exposed"),
                ("/backup.zip", "CRITICAL", "Backup file exposed"),
                ("/database.sql", "CRITICAL", "Database dump exposed"),
                ("/config.php", "CRITICAL", "Config file exposed"),
                ("/error_log", "MEDIUM", "Error log exposed"),
            ]
            for path, severity, desc in sensitive_paths:
                try:
                    check = await client.get(url.rstrip("/") + path, timeout=5, follow_redirects=False)
                    if check.status_code == 200:
                        issues.append({"severity": severity, "issue": f"{desc}: {path}", "fix": f"Immediately block access to {path} — serious security risk", "category": "Security"})
                        score -= 25 if severity == "CRITICAL" else 15
                except Exception:
                    pass

            # Data encryption check (forms sending passwords over HTTP)
            if urlparse(url).scheme == "http":
                password_inputs = soup.find_all("input", {"type": "password"})
                if password_inputs:
                    issues.append({"severity": "CRITICAL", "issue": "Password form submitted over unencrypted HTTP connection", "fix": "Move to HTTPS immediately — passwords are being sent in plain text", "category": "Security"})
                    score -= 30

    except Exception as e:
        issues.append({"severity": "INFO", "issue": f"Security check error: {str(e)}", "fix": "Verify site is reachable", "category": "Security"})

    # SSL Certificate deep check
    if urlparse(url).scheme == "https":
        try:
            loop = asyncio.get_event_loop()
            def get_cert():
                ctx = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=8) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        return ssock.getpeercert(), ssock.version()
            cert, tls_version = await loop.run_in_executor(None, get_cert)

            expire_str = cert.get("notAfter", "")
            if expire_str:
                expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_date - datetime.utcnow()).days
                if days_left < 0:
                    issues.append({"severity": "CRITICAL", "issue": "SSL certificate EXPIRED", "fix": "Renew SSL certificate immediately", "category": "Security"})
                    score -= 40
                elif days_left < 30:
                    issues.append({"severity": "HIGH", "issue": f"SSL certificate expires in {days_left} days", "fix": "Renew SSL certificate soon", "category": "Security"})
                    score -= 15
                else:
                    passed.append(f"SSL valid for {days_left} days")

            if tls_version in ["TLSv1", "TLSv1.1"]:
                issues.append({"severity": "HIGH", "issue": f"Outdated TLS: {tls_version}", "fix": "Upgrade to TLS 1.2 or 1.3", "category": "Security"})
                score -= 15
            else:
                passed.append(f"Modern TLS: {tls_version}")

        except ssl.SSLCertVerificationError:
            issues.append({"severity": "CRITICAL", "issue": "SSL certificate invalid or self-signed", "fix": "Get a valid SSL certificate", "category": "Security"})
            score -= 35
        except Exception:
            pass

    return {"score": max(0, score), "issues": issues, "passed": passed}


# ─────────────────────────────
# 2. PERFORMANCE CHECK (20% weight)
# ─────────────────────────────

async def check_performance(url: str) -> dict:
    issues = []
    passed = []
    score = 100
    load_time_ms = 0

    try:
        async with httpx.AsyncClient(
            timeout=30, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"}
        ) as client:
            start = time.time()
            r = await client.get(url)
            load_time_ms = round((time.time() - start) * 1000)
            headers = dict(r.headers)
            content = r.text
            soup = BeautifulSoup(content, "html.parser")

            # Page load time
            if load_time_ms > 5000:
                issues.append({"severity": "HIGH", "issue": f"Very slow load: {load_time_ms}ms (ideal <2000ms)", "fix": "Optimize images, enable caching, use CDN, minify CSS/JS", "category": "Performance"})
                score -= 25
            elif load_time_ms > 3000:
                issues.append({"severity": "MEDIUM", "issue": f"Slow load: {load_time_ms}ms (ideal <2000ms)", "fix": "Compress images and enable browser caching", "category": "Performance"})
                score -= 15
            elif load_time_ms > 2000:
                issues.append({"severity": "LOW", "issue": f"Load time slightly above ideal: {load_time_ms}ms", "fix": "Minor optimization needed", "category": "Performance"})
                score -= 8
            else:
                passed.append(f"Fast load time: {load_time_ms}ms")

            # Server response time (TTFB approximation)
            ttfb = load_time_ms * 0.3
            if ttfb > 600:
                issues.append({"severity": "MEDIUM", "issue": f"Slow server response time (~{round(ttfb)}ms)", "fix": "Upgrade hosting, enable server-side caching (Redis/Memcached), optimize database queries", "category": "Performance"})
                score -= 10

            # Compression
            content_encoding = headers.get("content-encoding", "")
            if content_encoding in ["gzip", "br", "deflate"]:
                passed.append(f"Compression enabled: {content_encoding}")
            else:
                issues.append({"severity": "MEDIUM", "issue": "HTTP compression not enabled", "fix": "Enable gzip or brotli compression — reduces page size by 60-80%", "category": "Performance"})
                score -= 12

            # Caching headers
            cache_control = headers.get("cache-control", "")
            if not cache_control:
                issues.append({"severity": "MEDIUM", "issue": "No Cache-Control header", "fix": "Add Cache-Control headers for static resources", "category": "Performance"})
                score -= 10
            else:
                passed.append("Cache-Control present")

            # Page size
            page_size_kb = len(content.encode()) / 1024
            if page_size_kb > 500:
                issues.append({"severity": "MEDIUM", "issue": f"Large page size: {round(page_size_kb)}KB (ideal <200KB)", "fix": "Minify HTML/CSS/JS, remove unused code", "category": "Performance"})
                score -= 12

            # Render-blocking scripts
            head = soup.find("head")
            if head:
                blocking = [s for s in head.find_all("script", src=True)
                           if not s.get("async") and not s.get("defer")]
                if blocking:
                    issues.append({"severity": "MEDIUM", "issue": f"{len(blocking)} render-blocking script(s) in <head>", "fix": "Add async or defer to script tags, or move to end of <body>", "category": "Performance"})
                    score -= 10

            # Resource optimization
            all_scripts = soup.find_all("script", src=True)
            unminified = [s for s in all_scripts
                         if s.get("src") and ".min." not in s.get("src", "")]
            if len(unminified) > 3:
                issues.append({"severity": "LOW", "issue": f"{len(unminified)} potentially unminified JS files", "fix": "Use minified versions of JavaScript files (.min.js)", "category": "Performance"})
                score -= 6

            all_styles = soup.find_all("link", rel="stylesheet")
            unminified_css = [s for s in all_styles
                             if s.get("href") and ".min." not in s.get("href", "")]
            if len(unminified_css) > 2:
                issues.append({"severity": "LOW", "issue": f"{len(unminified_css)} potentially unminified CSS files", "fix": "Use minified versions of CSS files (.min.css)", "category": "Performance"})
                score -= 5

            # Images without lazy loading
            images = soup.find_all("img")
            no_lazy = [img for img in images if not img.get("loading")]
            if len(no_lazy) > 5:
                issues.append({"severity": "LOW", "issue": f"{len(no_lazy)} images without lazy loading", "fix": 'Add loading="lazy" to images below the fold', "category": "Performance"})
                score -= 5

            # Images without dimensions
            no_dims = [img for img in images if not img.get("width") or not img.get("height")]
            if len(no_dims) > 3:
                issues.append({"severity": "LOW", "issue": f"{len(no_dims)} images missing width/height (causes layout shift)", "fix": "Add explicit width and height to all img tags", "category": "Performance"})
                score -= 5

            # Too many HTTP requests
            total_resources = len(all_scripts) + len(all_styles) + len(images)
            if total_resources > 50:
                issues.append({"severity": "MEDIUM", "issue": f"High number of resources: {total_resources} (scripts + styles + images)", "fix": "Bundle resources, use CSS sprites, combine JS files", "category": "Performance"})
                score -= 8

            # External resources
            external_resources = [
                s for s in soup.find_all(["script", "link", "img"])
                if (s.get("src") or s.get("href") or "").startswith("http")
                and urlparse(s.get("src") or s.get("href") or "").netloc != urlparse(url).netloc
            ]
            if len(external_resources) > 10:
                issues.append({"severity": "LOW", "issue": f"{len(external_resources)} external resource dependencies", "fix": "Self-host critical resources to avoid third-party slowdowns", "category": "Performance"})
                score -= 4

    except Exception as e:
        issues.append({"severity": "INFO", "issue": f"Performance check error: {str(e)}", "fix": "Verify site is reachable", "category": "Performance"})

    return {"score": max(0, score), "issues": issues, "passed": passed, "load_time_ms": load_time_ms}


# ─────────────────────────────
# 3. USABILITY CHECK (15% weight)
# ─────────────────────────────

async def check_usability(url: str) -> dict:
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

            # Mobile friendly — viewport meta tag
            viewport = soup.find("meta", attrs={"name": "viewport"})
            if not viewport:
                issues.append({"severity": "HIGH", "issue": "Missing viewport meta tag — site may not be mobile friendly", "fix": "Add: <meta name='viewport' content='width=device-width, initial-scale=1'>", "category": "Usability"})
                score -= 20
            else:
                passed.append("Viewport meta tag present (mobile friendly)")

            # Responsive design indicators
            responsive_indicators = [
                "@media", "max-width", "min-width",
                "flexbox", "flex", "grid", "bootstrap",
                "tailwind", "responsive"
            ]
            content_lower = content.lower()
            has_responsive = any(ind in content_lower for ind in responsive_indicators)
            if not has_responsive:
                issues.append({"severity": "MEDIUM", "issue": "No responsive design indicators found", "fix": "Implement responsive CSS using media queries, Flexbox, or a framework like Bootstrap", "category": "Usability"})
                score -= 12

            # Navigation — check for nav element
            nav = soup.find("nav")
            if not nav:
                issues.append({"severity": "MEDIUM", "issue": "No <nav> element found", "fix": "Use proper <nav> HTML element for navigation menus", "category": "Usability"})
                score -= 8
            else:
                passed.append("Navigation element present")

            # Accessibility — lang attribute
            html_tag = soup.find("html")
            if not html_tag or not html_tag.get("lang"):
                issues.append({"severity": "MEDIUM", "issue": "Missing lang attribute on <html> tag", "fix": "Add lang attribute: <html lang='en'>", "category": "Usability"})
                score -= 6
            else:
                passed.append(f"Language attribute: {html_tag.get('lang')}")

            # Accessibility — images alt text
            images = soup.find_all("img")
            no_alt = [img for img in images if not img.get("alt")]
            if no_alt:
                issues.append({"severity": "MEDIUM", "issue": f"{len(no_alt)} images missing alt text (accessibility)", "fix": "Add descriptive alt attributes to all images for screen readers", "category": "Usability"})
                score -= min(10, len(no_alt) * 2)
            else:
                passed.append("All images have alt text")

            # Accessibility — form labels
            inputs = soup.find_all("input", type=lambda t: t not in ["hidden", "submit", "button"])
            unlabeled = []
            for inp in inputs:
                inp_id = inp.get("id")
                if inp_id:
                    label = soup.find("label", attrs={"for": inp_id})
                    if not label:
                        unlabeled.append(inp_id)
                elif not inp.get("aria-label") and not inp.get("placeholder"):
                    unlabeled.append("unnamed input")
            if unlabeled:
                issues.append({"severity": "MEDIUM", "issue": f"{len(unlabeled)} form input(s) missing labels", "fix": "Add <label> elements or aria-label attributes to all form inputs", "category": "Usability"})
                score -= 8

            # Favicon
            favicon = soup.find("link", rel=lambda r: r and "icon" in r)
            if not favicon:
                issues.append({"severity": "LOW", "issue": "No favicon found", "fix": "Add a favicon.ico to improve branding and user experience", "category": "Usability"})
                score -= 4
            else:
                passed.append("Favicon present")

            # 404 page check
            try:
                test_404 = await client.get(
                    url.rstrip("/") + "/thispageshouldnotexist12345",
                    timeout=5
                )
                if test_404.status_code == 200:
                    issues.append({"severity": "LOW", "issue": "No proper 404 page — missing pages return 200 status", "fix": "Create a custom 404 error page that returns a proper 404 HTTP status code", "category": "Usability"})
                    score -= 5
                else:
                    passed.append("Custom 404 handling works")
            except Exception:
                pass

            # Search functionality check
            search_input = soup.find("input", attrs={"type": "search"}) or \
                          soup.find("input", attrs={"name": re.compile(r'search|query|q', re.I)})
            if not search_input:
                issues.append({"severity": "LOW", "issue": "No search functionality detected", "fix": "Consider adding a search feature for better navigation on content-heavy sites", "category": "Usability"})
                score -= 3

            # Readability — font size check
            if "font-size: 10px" in content or "font-size:10px" in content or \
               "font-size: 11px" in content or "font-size:11px" in content:
                issues.append({"severity": "LOW", "issue": "Very small font size detected (below 12px)", "fix": "Use minimum 14-16px font size for body text for readability", "category": "Usability"})
                score -= 5

            # Skip navigation link (accessibility)
            skip_link = soup.find("a", attrs={"href": "#main-content"}) or \
                       soup.find("a", string=re.compile(r'skip', re.I))
            if not skip_link:
                issues.append({"severity": "LOW", "issue": "No skip navigation link for keyboard/screen reader users", "fix": "Add a 'Skip to main content' link for accessibility", "category": "Usability"})
                score -= 3

    except Exception as e:
        issues.append({"severity": "INFO", "issue": f"Usability check error: {str(e)}", "fix": "Verify site is reachable", "category": "Usability"})

    return {"score": max(0, score), "issues": issues, "passed": passed}


# ─────────────────────────────
# 4. SEO CHECK (10% weight)
# ─────────────────────────────

async def check_seo(url: str) -> dict:
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
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"

            # Title
            title = soup.find("title")
            if not title or not title.text.strip():
                issues.append({"severity": "HIGH", "issue": "Missing <title> tag", "fix": "Add a descriptive title (50-60 chars) to every page", "category": "SEO"})
                score -= 15
            elif len(title.text.strip()) > 60:
                issues.append({"severity": "LOW", "issue": f"Title too long: {len(title.text.strip())} chars (ideal 50-60)", "fix": "Shorten page title to under 60 characters", "category": "SEO"})
                score -= 5
            elif len(title.text.strip()) < 20:
                issues.append({"severity": "MEDIUM", "issue": f"Title too short: {len(title.text.strip())} chars", "fix": "Make the title more descriptive (50-60 characters)", "category": "SEO"})
                score -= 8
            else:
                passed.append(f"Good title: {title.text.strip()[:40]}")

            # Meta description
            meta_desc = soup.find("meta", attrs={"name": "description"})
            if not meta_desc or not meta_desc.get("content"):
                issues.append({"severity": "HIGH", "issue": "Missing meta description", "fix": "Add meta description (150-160 chars)", "category": "SEO"})
                score -= 12
            else:
                passed.append("Meta description present")

            # H1
            h1_tags = soup.find_all("h1")
            if not h1_tags:
                issues.append({"severity": "HIGH", "issue": "Missing H1 tag", "fix": "Add exactly one H1 tag with main page topic/keyword", "category": "SEO"})
                score -= 12
            elif len(h1_tags) > 1:
                issues.append({"severity": "MEDIUM", "issue": f"Multiple H1 tags ({len(h1_tags)})", "fix": "Use only one H1 per page", "category": "SEO"})
                score -= 6
            else:
                passed.append("Single H1 present")

            # Canonical
            canonical = soup.find("link", attrs={"rel": "canonical"})
            if not canonical:
                issues.append({"severity": "MEDIUM", "issue": "Missing canonical URL tag", "fix": "Add canonical URL to prevent duplicate content issues", "category": "SEO"})
                score -= 8

            # Sitemap
            try:
                sitemap = await client.get(f"{base}/sitemap.xml", timeout=5)
                if sitemap.status_code == 200:
                    passed.append("sitemap.xml found")
                else:
                    issues.append({"severity": "MEDIUM", "issue": "No sitemap.xml found", "fix": "Create and submit a sitemap.xml", "category": "SEO"})
                    score -= 8
            except Exception:
                pass

            # Robots.txt
            try:
                robots = await client.get(f"{base}/robots.txt", timeout=5)
                if robots.status_code == 200:
                    passed.append("robots.txt found")
                else:
                    issues.append({"severity": "LOW", "issue": "No robots.txt found", "fix": "Create a robots.txt to guide search crawlers", "category": "SEO"})
                    score -= 4
            except Exception:
                pass

            # Structured data (Schema.org)
            schema = soup.find("script", attrs={"type": "application/ld+json"})
            if not schema:
                issues.append({"severity": "LOW", "issue": "No structured data (Schema.org markup) found", "fix": "Add JSON-LD structured data to improve search result appearance", "category": "SEO"})
                score -= 6
            else:
                passed.append("Structured data found")

            # Open Graph
            og_tags = {
                "og:title": soup.find("meta", attrs={"property": "og:title"}),
                "og:description": soup.find("meta", attrs={"property": "og:description"}),
                "og:image": soup.find("meta", attrs={"property": "og:image"})
            }
            missing_og = [k for k, v in og_tags.items() if not v]
            if missing_og:
                issues.append({"severity": "LOW", "issue": f"Missing Open Graph tags: {', '.join(missing_og)}", "fix": "Add Open Graph tags for better social media sharing", "category": "SEO"})
                score -= 5
            else:
                passed.append("Open Graph tags present")

            # Images alt text for SEO
            images = soup.find_all("img")
            no_alt = [img for img in images if not img.get("alt")]
            if no_alt:
                issues.append({"severity": "MEDIUM", "issue": f"{len(no_alt)} images missing alt text (affects SEO)", "fix": "Add keyword-relevant alt text to all images", "category": "SEO"})
                score -= min(10, len(no_alt) * 2)

            # Mobile SEO
            viewport = soup.find("meta", attrs={"name": "viewport"})
            if not viewport:
                issues.append({"severity": "HIGH", "issue": "Not mobile optimized — Google penalizes non-mobile sites", "fix": "Add viewport meta tag and make site responsive", "category": "SEO"})
                score -= 15
            else:
                passed.append("Mobile SEO viewport present")

            # Noindex check
            robots_meta = soup.find("meta", attrs={"name": "robots"})
            if robots_meta and "noindex" in robots_meta.get("content", "").lower():
                issues.append({"severity": "CRITICAL", "issue": "Page has noindex — search engines will NOT index this", "fix": "Remove noindex if you want this page in search results", "category": "SEO"})
                score -= 25

            # Heading structure
            if not soup.find_all("h2") and len(soup.get_text()) > 500:
                issues.append({"severity": "LOW", "issue": "No H2 subheadings on content page", "fix": "Add H2/H3 tags to structure content for SEO", "category": "SEO"})
                score -= 4

    except Exception as e:
        issues.append({"severity": "INFO", "issue": f"SEO check error: {str(e)}", "fix": "Verify site is reachable", "category": "SEO"})

    return {"score": max(0, score), "issues": issues, "passed": passed}


# ─────────────────────────────
# 5. TRUST CHECK (10% weight)
# ─────────────────────────────

async def check_trust(url: str, domain: str) -> dict:
    issues = []
    passed = []
    score = 100

    try:
        async with httpx.AsyncClient(
            timeout=15, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"}
        ) as client:

            # Domain age via WHOIS-like heuristic
            try:
                whois_r = await client.get(
                    f"https://api.whoisfreaks.com/v1.0/whois?whois=live&domainName={domain}&apiKey=free",
                    timeout=8
                )
                if whois_r.status_code == 200:
                    data = whois_r.json()
                    created = data.get("create_date", "")
                    if created:
                        try:
                            created_date = datetime.strptime(created[:10], "%Y-%m-%d")
                            age_days = (datetime.utcnow() - created_date).days
                            if age_days < 90:
                                issues.append({"severity": "HIGH", "issue": f"Very new domain: registered {age_days} days ago", "fix": "New domains are often used for phishing — build trust over time", "category": "Trust"})
                                score -= 20
                            elif age_days < 365:
                                issues.append({"severity": "MEDIUM", "issue": f"Relatively new domain: {age_days} days old", "fix": "Domain is less than 1 year old — trust increases with age", "category": "Trust"})
                                score -= 10
                            else:
                                passed.append(f"Established domain: {round(age_days/365, 1)} years old")
                        except Exception:
                            pass
            except Exception:
                pass

            # Privacy policy check
            r = await client.get(url)
            soup = BeautifulSoup(r.text, "html.parser")
            content_lower = r.text.lower()

            privacy_link = soup.find("a", string=re.compile(r'privacy', re.I)) or \
                          "privacy policy" in content_lower or \
                          "privacy-policy" in content_lower
            if privacy_link:
                passed.append("Privacy policy found")
            else:
                issues.append({"severity": "MEDIUM", "issue": "No privacy policy found", "fix": "Add a privacy policy page — required by GDPR and builds user trust", "category": "Trust"})
                score -= 12

            # Terms of service
            tos_link = soup.find("a", string=re.compile(r'terms|conditions', re.I)) or \
                      "terms of service" in content_lower or \
                      "terms and conditions" in content_lower
            if tos_link:
                passed.append("Terms of service found")
            else:
                issues.append({"severity": "LOW", "issue": "No terms of service found", "fix": "Add Terms of Service page for legal protection and user trust", "category": "Trust"})
                score -= 6

            # Contact information
            contact_indicators = ["contact", "email", "phone", "address", "tel:"]
            has_contact = any(ind in content_lower for ind in contact_indicators)
            if has_contact:
                passed.append("Contact information present")
            else:
                issues.append({"severity": "MEDIUM", "issue": "No contact information found", "fix": "Add contact details — email, phone, or contact form builds trust", "category": "Trust"})
                score -= 10

            # About page
            about_link = soup.find("a", string=re.compile(r'about', re.I)) or \
                        "about us" in content_lower
            if about_link:
                passed.append("About page found")
            else:
                issues.append({"severity": "LOW", "issue": "No about page found", "fix": "Add an About Us page to build credibility with visitors", "category": "Trust"})
                score -= 5

            # HTTPS contributes to trust
            if urlparse(url).scheme == "https":
                passed.append("HTTPS contributes to domain trust")
            else:
                issues.append({"severity": "HIGH", "issue": "HTTP site — browsers show 'Not Secure' warning", "fix": "Switch to HTTPS — browsers actively warn users about HTTP sites", "category": "Trust"})
                score -= 20

            # DNS uptime / reliability
            try:
                loop = asyncio.get_event_loop()
                ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
                passed.append(f"DNS resolves correctly to {ip}")
            except Exception:
                issues.append({"severity": "HIGH", "issue": "DNS resolution failed", "fix": "Check DNS configuration for this domain", "category": "Trust"})
                score -= 20

            # WWW redirect check
            try:
                www_url = f"https://www.{domain}" if not domain.startswith("www") else url
                www_r = await client.get(www_url, timeout=8, follow_redirects=False)
                if www_r.status_code in [301, 302]:
                    passed.append("WWW redirect configured")
                else:
                    issues.append({"severity": "LOW", "issue": "No consistent www/non-www redirect", "fix": "Set up a 301 redirect from www to non-www (or vice versa) for consistency", "category": "Trust"})
                    score -= 5
            except Exception:
                pass

    except Exception as e:
        issues.append({"severity": "INFO", "issue": f"Trust check error: {str(e)}", "fix": "Verify site is reachable", "category": "Trust"})

    return {"score": max(0, score), "issues": issues, "passed": passed}


# ─────────────────────────────
# 6. CONTENT QUALITY CHECK (5% weight)
# ─────────────────────────────

async def check_content_quality(url: str) -> dict:
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

            # Remove scripts and styles
            for tag in soup(["script", "style", "nav", "footer"]):
                tag.decompose()

            text = soup.get_text(separator=" ", strip=True)
            words = [w for w in text.split() if len(w) > 2]
            word_count = len(words)

            # Content length
            if word_count < 100:
                issues.append({"severity": "HIGH", "issue": f"Very thin content: only {word_count} words", "fix": "Add more meaningful content to the page (minimum 300+ words recommended)", "category": "Content"})
                score -= 20
            elif word_count < 300:
                issues.append({"severity": "MEDIUM", "issue": f"Low content volume: {word_count} words", "fix": "Expand page content for better SEO and user value", "category": "Content"})
                score -= 10
            else:
                passed.append(f"Good content volume: {word_count} words")

            # Spam content check
            spam_patterns = [
                r'click here now', r'buy now', r'free money',
                r'make money fast', r'guaranteed income',
                r'limited time offer', r'act now',
                r'you have been selected', r'congratulations you won'
            ]
            text_lower = text.lower()
            spam_found = [p for p in spam_patterns if re.search(p, text_lower)]
            if spam_found:
                issues.append({"severity": "HIGH", "issue": f"Spam-like content patterns detected: {', '.join(spam_found[:2])}", "fix": "Remove clickbait and spam language — it hurts trust and SEO rankings", "category": "Content"})
                score -= 20

            # Broken/empty headings
            all_headings = soup.find_all(["h1", "h2", "h3", "h4"])
            empty_headings = [h for h in all_headings if not h.get_text(strip=True)]
            if empty_headings:
                issues.append({"severity": "LOW", "issue": f"{len(empty_headings)} empty heading tag(s) found", "fix": "Remove or fill empty heading tags", "category": "Content"})
                score -= 5

            # Placeholder content
            placeholder_patterns = ["lorem ipsum", "placeholder", "sample text", "dummy text", "coming soon"]
            placeholder_found = [p for p in placeholder_patterns if p in text_lower]
            if placeholder_found:
                issues.append({"severity": "MEDIUM", "issue": "Placeholder/lorem ipsum content detected", "fix": "Replace placeholder text with real, meaningful content", "category": "Content"})
                score -= 15

            # Copyright/last updated
            copyright_pattern = re.search(r'©|copyright|\d{4}', text_lower)
            if copyright_pattern:
                passed.append("Copyright/year info present")
            else:
                issues.append({"severity": "LOW", "issue": "No copyright or date information found", "fix": "Add copyright notice and date to build trust", "category": "Content"})
                score -= 4

    except Exception as e:
        issues.append({"severity": "INFO", "issue": f"Content check error: {str(e)}", "fix": "Verify site is reachable", "category": "Content"})

    return {"score": max(0, score), "issues": issues, "passed": passed}


# ─────────────────────────────
# 7. BROKEN LINKS CHECK
# (included in overall audit but not in weighted score directly)
# ─────────────────────────────

async def check_broken_links(url: str, max_links: int = 80) -> dict:
    issues = []
    passed = []
    score = 100
    broken_links = []
    total_checked = 0

    try:
        async with httpx.AsyncClient(
            timeout=10, follow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0"}
        ) as client:
            r = await client.get(url, follow_redirects=True)
            soup = BeautifulSoup(r.text, "html.parser")

            # Collect all links and resources
            to_check = set()
            for tag in soup.find_all(["a", "link"], href=True):
                href = tag.get("href", "")
                if href.startswith(("mailto:", "tel:", "javascript:", "#")):
                    continue
                full = urljoin(url, href)
                if full.startswith("http"):
                    to_check.add(full)

            for tag in soup.find_all(["img", "script"], src=True):
                src = tag.get("src", "")
                if src.startswith("http"):
                    to_check.add(src)

            to_check = list(to_check)[:max_links]
            semaphore = asyncio.Semaphore(10)

            async def check_link(link_url):
                async with semaphore:
                    try:
                        await asyncio.sleep(0.05)
                        resp = await client.head(link_url, timeout=8)
                        if resp.status_code == 405:
                            resp = await client.get(link_url, timeout=8, follow_redirects=True)
                        return {"url": link_url, "status": resp.status_code, "ok": resp.status_code < 400}
                    except Exception as e:
                        return {"url": link_url, "status": 0, "ok": False, "error": str(e)[:60]}

            results = await asyncio.gather(*[check_link(l) for l in to_check])
            total_checked = len(results)

            for result in results:
                if not result["ok"]:
                    status = result["status"]
                    broken_links.append({"url": result["url"], "status": status})
                    if status == 404:
                        issues.append({"severity": "HIGH", "issue": f"Broken link (404): {result['url'][:80]}", "fix": "Update or remove this broken link", "category": "Broken Links"})
                        score -= 3
                    elif status >= 500:
                        issues.append({"severity": "HIGH", "issue": f"Server error ({status}): {result['url'][:80]}", "fix": "Fix the server error on this resource", "category": "Broken Links"})
                        score -= 5
                    elif status == 0:
                        issues.append({"severity": "MEDIUM", "issue": f"Unreachable resource: {result['url'][:80]}", "fix": "Check if this resource still exists", "category": "Broken Links"})
                        score -= 2

            if not broken_links:
                passed.append(f"All {total_checked} links and resources are working")

    except Exception as e:
        issues.append({"severity": "INFO", "issue": f"Link check error: {str(e)}", "fix": "Verify site is reachable", "category": "Broken Links"})

    return {
        "score": max(0, score),
        "issues": issues,
        "passed": passed,
        "broken_links": broken_links,
        "total_checked": total_checked
    }


# ─────────────────────────────
# MASTER AUDIT RUNNER
# ─────────────────────────────

async def run_full_website_audit(url: str) -> dict:
    domain = urlparse(url).netloc.replace("www.", "")

    # Run all 7 checks in parallel
    results = await asyncio.gather(
        check_security(url, domain),
        check_performance(url),
        check_usability(url),
        check_seo(url),
        check_trust(url, domain),
        check_content_quality(url),
        check_broken_links(url),
        return_exceptions=True
    )

    security    = results[0] if not isinstance(results[0], Exception) else {"score": 0, "issues": [], "passed": []}
    performance = results[1] if not isinstance(results[1], Exception) else {"score": 0, "issues": [], "passed": [], "load_time_ms": 0}
    usability   = results[2] if not isinstance(results[2], Exception) else {"score": 0, "issues": [], "passed": []}
    seo         = results[3] if not isinstance(results[3], Exception) else {"score": 0, "issues": [], "passed": []}
    trust       = results[4] if not isinstance(results[4], Exception) else {"score": 0, "issues": [], "passed": []}
    content     = results[5] if not isinstance(results[5], Exception) else {"score": 0, "issues": [], "passed": []}
    broken_links = results[6] if not isinstance(results[6], Exception) else {"score": 0, "issues": [], "passed": [], "broken_links": [], "total_checked": 0}

    # Weighted overall score
    # Security 40% | Performance 20% | Usability 15% | SEO 10% | Trust 10% | Content 5%
    overall_score = round(
        security["score"]    * 0.40 +
        performance["score"] * 0.20 +
        usability["score"]   * 0.15 +
        seo["score"]         * 0.10 +
        trust["score"]       * 0.10 +
        content["score"]     * 0.05
    )

    if overall_score >= 90:   grade = "A+"
    elif overall_score >= 80: grade = "A"
    elif overall_score >= 70: grade = "B"
    elif overall_score >= 60: grade = "C"
    elif overall_score >= 40: grade = "D"
    else:                     grade = "F"

    all_issues = (
        security.get("issues", []) +
        performance.get("issues", []) +
        usability.get("issues", []) +
        seo.get("issues", []) +
        trust.get("issues", []) +
        content.get("issues", []) +
        broken_links.get("issues", [])
    )
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_issues.sort(key=lambda x: severity_order.get(x["severity"], 5))

    critical_count = len([i for i in all_issues if i["severity"] == "CRITICAL"])
    high_count     = len([i for i in all_issues if i["severity"] == "HIGH"])
    medium_count   = len([i for i in all_issues if i["severity"] == "MEDIUM"])
    low_count      = len([i for i in all_issues if i["severity"] == "LOW"])

    return {
        "url": url,
        "overall_score": overall_score,
        "grade": grade,
        "critical_issues": critical_count,
        "high_issues": high_count,
        "medium_issues": medium_count,
        "low_issues": low_count,
        "total_issues": len(all_issues),
        "all_issues": all_issues,
        "security": security,
        "performance": performance,
        "usability": usability,
        "seo": seo,
        "trust": trust,
        "content": content,
        "broken_links": broken_links,
        "score_weights": {
            "security":    {"weight": 0.40, "label": "Security",       "score": security["score"]},
            "performance": {"weight": 0.20, "label": "Performance",    "score": performance["score"]},
            "usability":   {"weight": 0.15, "label": "Usability",      "score": usability["score"]},
            "seo":         {"weight": 0.10, "label": "SEO",            "score": seo["score"]},
            "trust":       {"weight": 0.10, "label": "Trust",          "score": trust["score"]},
            "content":     {"weight": 0.05, "label": "Content Quality","score": content["score"]},
        },
        "timestamp": datetime.utcnow().isoformat()
    }
