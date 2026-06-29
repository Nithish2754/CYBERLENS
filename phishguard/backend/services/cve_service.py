import httpx
import re
from bs4 import BeautifulSoup

# Known technology fingerprints from HTTP headers and page content
TECH_FINGERPRINTS = {
    "Apache": {
        "header": "server",
        "pattern": r"Apache[/ ]([\d.]+)",
        "cve_search": "Apache HTTP Server"
    },
    "Nginx": {
        "header": "server",
        "pattern": r"nginx[/ ]([\d.]+)",
        "cve_search": "Nginx"
    },
    "PHP": {
        "header": "x-powered-by",
        "pattern": r"PHP[/ ]([\d.]+)",
        "cve_search": "PHP"
    },
    "WordPress": {
        "content_pattern": r'content="WordPress ([\d.]+)"',
        "cve_search": "WordPress"
    },
    "Drupal": {
        "content_pattern": r'Drupal ([\d.]+)',
        "cve_search": "Drupal"
    },
    "Joomla": {
        "content_pattern": r'Joomla[! ]*([\d.]+)',
        "cve_search": "Joomla"
    },
    "ASP.NET": {
        "header": "x-aspnet-version",
        "pattern": r"([\d.]+)",
        "cve_search": "ASP.NET"
    },
    "OpenSSL": {
        "header": "server",
        "pattern": r"OpenSSL[/ ]([\d.]+[a-z]*)",
        "cve_search": "OpenSSL"
    },
    "IIS": {
        "header": "server",
        "pattern": r"IIS[/ ]([\d.]+)",
        "cve_search": "Microsoft IIS"
    },
    "jQuery": {
        "content_pattern": r'jquery[.-]([\d.]+)(?:\.min)?\.js',
        "cve_search": "jQuery"
    },
    "Bootstrap": {
        "content_pattern": r'bootstrap[.-]([\d.]+)(?:\.min)?\.(?:css|js)',
        "cve_search": "Bootstrap"
    }
}

async def detect_technologies(url: str, headers: dict, content: str) -> list:
    detected = []

    for tech_name, fingerprint in TECH_FINGERPRINTS.items():
        version = None

        # Check HTTP headers
        if "header" in fingerprint:
            header_value = headers.get(fingerprint["header"], "")
            if header_value:
                pattern = fingerprint.get("pattern", "")
                if pattern:
                    match = re.search(pattern, header_value, re.IGNORECASE)
                    if match:
                        version = match.group(1)
                        detected.append({
                            "name": tech_name,
                            "version": version,
                            "detected_from": "HTTP Header",
                            "cve_search": fingerprint["cve_search"]
                        })
                        continue

        # Check page content
        if "content_pattern" in fingerprint:
            match = re.search(fingerprint["content_pattern"], content, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else "unknown"
                detected.append({
                    "name": tech_name,
                    "version": version,
                    "detected_from": "Page Content",
                    "cve_search": fingerprint["cve_search"]
                })

    # Additional detection from meta generator tag
    soup = BeautifulSoup(content, "html.parser")
    generator = soup.find("meta", attrs={"name": "generator"})
    if generator:
        gen_content = generator.get("content", "")
        for tech_name, fingerprint in TECH_FINGERPRINTS.items():
            if tech_name.lower() in gen_content.lower():
                version_match = re.search(r'[\d.]+', gen_content)
                version = version_match.group() if version_match else "unknown"
                if not any(d["name"] == tech_name for d in detected):
                    detected.append({
                        "name": tech_name,
                        "version": version,
                        "detected_from": "Meta Generator",
                        "cve_search": fingerprint["cve_search"]
                    })

    return detected


async def lookup_cves(technology: str, version: str) -> list:
    cves = []

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # Use NVD (National Vulnerability Database) free API
            # No API key required for basic queries
            response = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={
                    "keywordSearch": f"{technology} {version}",
                    "resultsPerPage": 5,
                    "startIndex": 0
                },
                headers={"User-Agent": "CyberLens-CVE-Scanner/1.0"}
            )

            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                for vuln in vulnerabilities[:5]:
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")
                    descriptions = cve.get("descriptions", [])
                    description = next(
                        (d["value"] for d in descriptions if d["lang"] == "en"),
                        "No description available"
                    )

                    # Get CVSS score
                    metrics = cve.get("metrics", {})
                    cvss_score = None
                    severity = "UNKNOWN"

                    # Try CVSS v3.1 first, then v3.0, then v2.0
                    for cvss_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        if cvss_version in metrics:
                            cvss_data = metrics[cvss_version][0].get("cvssData", {})
                            cvss_score = cvss_data.get("baseScore")
                            severity = cvss_data.get("baseSeverity", "UNKNOWN")
                            break

                    if cvss_score:
                        cves.append({
                            "cve_id": cve_id,
                            "description": description[:200],
                            "cvss_score": cvss_score,
                            "severity": severity,
                            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                        })

    except Exception as e:
        print(f"CVE lookup error for {technology}: {e}")

    return cves


async def run_cve_scan(url: str) -> dict:
    issues = []
    passed = []
    detected_technologies = []
    all_cves = []

    try:
        async with httpx.AsyncClient(
            timeout=15,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"}
        ) as client:
            r = await client.get(url)
            headers = dict(r.headers)
            content = r.text

            # Detect technologies
            detected_technologies = await detect_technologies(url, headers, content)

            if not detected_technologies:
                passed.append("No specific technology versions detected in headers or content")
                return {
                    "score": 100,
                    "issues": issues,
                    "passed": passed,
                    "technologies": [],
                    "cves": []
                }

            # Look up CVEs for each detected technology
            score = 100
            for tech in detected_technologies:
                tech_cves = await lookup_cves(
                    tech["cve_search"],
                    tech["version"]
                )

                if tech_cves:
                    tech["cves"] = tech_cves
                    all_cves.extend(tech_cves)

                    # Score based on CVE severity
                    critical_cves = [c for c in tech_cves if c["severity"] in ["CRITICAL", "HIGH"]]
                    medium_cves = [c for c in tech_cves if c["severity"] == "MEDIUM"]

                    if critical_cves:
                        issues.append({
                            "severity": "CRITICAL",
                            "issue": f"{tech['name']} {tech['version']} has {len(critical_cves)} critical/high CVE(s)",
                            "fix": f"Update {tech['name']} to the latest version immediately. Known CVEs: {', '.join([c['cve_id'] for c in critical_cves[:3]])}",
                            "category": "CVE",
                            "standard": "CVE Detection",
                            "cves": critical_cves
                        })
                        score -= min(40, len(critical_cves) * 15)
                    elif medium_cves:
                        issues.append({
                            "severity": "MEDIUM",
                            "issue": f"{tech['name']} {tech['version']} has {len(medium_cves)} medium CVE(s)",
                            "fix": f"Plan update for {tech['name']} — medium severity vulnerabilities present",
                            "category": "CVE",
                            "standard": "CVE Detection",
                            "cves": medium_cves
                        })
                        score -= min(20, len(medium_cves) * 8)
                    else:
                        passed.append(f"{tech['name']} {tech['version']} — no critical CVEs found")
                else:
                    tech["cves"] = []
                    passed.append(f"{tech['name']} {tech['version']} — no CVEs matched")

    except Exception as e:
        issues.append({
            "severity": "INFO",
            "issue": f"CVE scan error: {str(e)}",
            "fix": "Verify site is reachable",
            "category": "CVE",
            "standard": "CVE Detection"
        })

    return {
        "score": max(0, score),
        "issues": issues,
        "passed": passed,
        "technologies": detected_technologies,
        "cves": all_cves,
        "total_cves_found": len(all_cves)
    }
