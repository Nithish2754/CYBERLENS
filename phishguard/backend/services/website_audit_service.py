"""Website audit service

Provides a lightweight, robust website audit that aggregates security,
performance, SEO and broken-link checks. Designed as a safe, async
implementation using httpx and BeautifulSoup. Returns a stable JSON-like
shape consumed by the routers and AI summarizer.
"""

import asyncio
from datetime import datetime
from urllib.parse import urlparse, urljoin
import httpx
from bs4 import BeautifulSoup

from services.security_audit_service import run_security_audit


async def check_performance(url: str) -> dict:
    issues = []
    passed = []
    score = 100
    load_time_ms = None

    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"}) as client:
            start = datetime.utcnow().timestamp()
            r = await client.get(url)
            load_time_ms = int((datetime.utcnow().timestamp() - start) * 1000)

            if load_time_ms is None:
                pass
            elif load_time_ms > 5000:
                issues.append({"severity": "HIGH", "issue": f"Very slow page load: {load_time_ms}ms", "fix": "Optimize images, enable caching, use a CDN", "category": "Performance"})
                score -= 25
            elif load_time_ms > 3000:
                issues.append({"severity": "MEDIUM", "issue": f"Slow page load: {load_time_ms}ms", "fix": "Optimize assets and enable caching", "category": "Performance"})
                score -= 15
            elif load_time_ms > 2000:
                issues.append({"severity": "LOW", "issue": f"Page load slightly above ideal: {load_time_ms}ms", "fix": "Minor optimizations recommended", "category": "Performance"})
                score -= 8
            else:
                passed.append(f"Fast page load: {load_time_ms}ms")

            headers = {k.lower(): v for k, v in r.headers.items()}
            encoding = headers.get("content-encoding", "")
            if not encoding:
                issues.append({"severity": "MEDIUM", "issue": "HTTP compression not enabled", "fix": "Enable gzip or brotli compression", "category": "Performance"})
                score -= 12
            else:
                passed.append(f"Compression: {encoding}")

            cache = headers.get("cache-control", "")
            if not cache:
                issues.append({"severity": "MEDIUM", "issue": "No Cache-Control header", "fix": "Add Cache-Control for static assets", "category": "Performance"})
                score -= 10
            else:
                passed.append("Cache-Control present")

            size_kb = len(r.content) / 1024
            if size_kb > 500:
                issues.append({"severity": "MEDIUM", "issue": f"Large page size: {int(size_kb)}KB", "fix": "Minify HTML, compress images", "category": "Performance"})
                score -= 12

    except Exception as e:
        issues.append({"severity": "INFO", "issue": f"Performance check failed: {str(e)}", "fix": "Ensure site is reachable", "category": "Performance"})

    return {"score": max(0, score), "issues": issues, "passed": passed, "load_time_ms": load_time_ms}


async def check_seo(url: str) -> dict:
    issues = []
    passed = []
    score = 100

    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"}) as client:
            r = await client.get(url)
            soup = BeautifulSoup(r.text, "html.parser")

            # Title
            title = soup.title.string.strip() if soup.title and soup.title.string else ""
            if not title:
                issues.append({"severity": "MEDIUM", "issue": "Missing <title> tag", "fix": "Add a concise title tag", "category": "SEO"})
                score -= 10
            else:
                passed.append("Title present")

            # Meta description
            desc = ""
            tag = soup.find("meta", attrs={"name": "description"})
            if tag and tag.get("content"):
                desc = tag.get("content").strip()
            if not desc:
                issues.append({"severity": "LOW", "issue": "Missing meta description", "fix": "Add a meta description tag for better search snippets", "category": "SEO"})
                score -= 6
            else:
                passed.append("Meta description present")

            # H1 presence
            h1 = soup.find("h1")
            if not h1:
                issues.append({"severity": "LOW", "issue": "Missing H1 heading", "fix": "Add an H1 heading to the page", "category": "SEO"})
                score -= 5
            else:
                passed.append("H1 present")

            # Robots
            robots = soup.find("meta", attrs={"name": "robots"})
            if robots and robots.get("content") and "noindex" in robots.get("content"):
                issues.append({"severity": "HIGH", "issue": "Page set to noindex", "fix": "Remove noindex unless intentional", "category": "SEO"})
                score -= 30

    except Exception as e:
        issues.append({"severity": "INFO", "issue": f"SEO check failed: {str(e)}", "fix": "Ensure site is reachable", "category": "SEO"})

    return {"score": max(0, score), "issues": issues, "passed": passed}


async def check_broken_links(url: str, max_pages: int = 25) -> dict:
    issues = []
    passed = []
    broken = []
    score = 100

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    to_visit = {url}
    visited = set()

    async with httpx.AsyncClient(timeout=15, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"}) as client:
        while to_visit and len(visited) < max_pages:
            current = to_visit.pop()
            visited.add(current)
            try:
                r = await client.get(current)
                soup = BeautifulSoup(r.text, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href.startswith("#") or href.lower().startswith("mailto:"):
                        continue
                    full = urljoin(base, href)
                    if full in visited or full in to_visit:
                        continue
                    # Only check same-domain links to avoid long external crawls
                    if urlparse(full).netloc != parsed.netloc:
                        continue
                    try:
                        resp = await client.head(full, follow_redirects=True)
                        if resp.status_code >= 400:
                            broken.append({"url": full, "status": resp.status_code})
                        else:
                            passed.append(f"{full} OK")
                    except Exception:
                        broken.append({"url": full, "status": "error"})
                    to_visit.add(full)
            except Exception:
                issues.append({"severity": "INFO", "issue": f"Failed to fetch {current}", "category": "Broken Links"})

    if broken:
        issues.append({"severity": "MEDIUM", "issue": f"Found {len(broken)} broken link(s)", "fix": "Fix or remove broken internal links", "category": "Broken Links"})
        score -= min(50, len(broken) * 5)
    else:
        passed.append("No broken internal links found")

    return {"score": max(0, score), "issues": issues, "passed": passed, "broken_links": broken}


async def run_full_website_audit(url: str) -> dict:
    """Aggregates security, performance, SEO and broken-link checks and
    returns a unified audit report with an overall score and category grade.
    """
    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "")

    # Run security audit (existing service) plus other checks concurrently
    tasks = [
        asyncio.create_task(run_security_audit(url)),
        asyncio.create_task(check_performance(url)),
        asyncio.create_task(check_seo(url)),
        asyncio.create_task(check_broken_links(url, max_pages=25)),
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Normalize results and handle exceptions
    security_res = results[0] if not isinstance(results[0], Exception) else {"security_score": 0, "findings": [{"severity":"INFO","issue":str(results[0])}], "grade": "F"}
    perf_res = results[1] if not isinstance(results[1], Exception) else {"score": 0, "issues": [{"severity":"INFO","issue": str(results[1])}], "passed": [], "load_time_ms": None}
    seo_res = results[2] if not isinstance(results[2], Exception) else {"score": 0, "issues": [{"severity":"INFO","issue": str(results[2])}], "passed": []}
    broken_res = results[3] if not isinstance(results[3], Exception) else {"score": 0, "issues": [{"severity":"INFO","issue": str(results[3])}], "passed": [], "broken_links": []}

    # Combine scoring: weighted average (security 40%, performance 30%, seo 20%, broken links 10%)
    sec_score = security_res.get("security_score", security_res.get("score", 0))
    perf_score = perf_res.get("score", 0)
    seo_score = seo_res.get("score", 0)
    broken_score = broken_res.get("score", 0)

    overall_score = int((0.4 * sec_score) + (0.3 * perf_score) + (0.2 * seo_score) + (0.1 * broken_score))

    if overall_score >= 90:
        grade = "A"
    elif overall_score >= 75:
        grade = "B"
    elif overall_score >= 60:
        grade = "C"
    elif overall_score >= 40:
        grade = "D"
    else:
        grade = "F"

    all_issues = []
    # Normalize findings lists
    all_issues.extend(security_res.get("findings", []))
    all_issues.extend(perf_res.get("issues", []))
    all_issues.extend(seo_res.get("issues", []))
    all_issues.extend(broken_res.get("issues", []))

    report = {
        "url": url,
        "overall_score": overall_score,
        "grade": grade,
        "timestamp": datetime.utcnow().isoformat(),
        "security": security_res,
        "performance": perf_res,
        "seo": seo_res,
        "broken_links": broken_res,
        "all_issues": all_issues,
        "total_issues": len(all_issues),
    }

    return report
