import httpx
import hashlib
from config import settings

async def check_alienvault_otx(domain: str, url: str) -> dict:
    issues = []
    passed = []
    score = 100
    details = {}

    if not settings.OTX_API_KEY:
        return {
            "available": False,
            "error": "No OTX API key configured",
            "score": 100,
            "issues": [],
            "passed": []
        }

    clean_domain = domain.replace("www.", "")

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            headers = {"X-OTX-API-KEY": settings.OTX_API_KEY}

            # Domain reputation
            domain_r = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{clean_domain}/general",
                headers=headers
            )

            if domain_r.status_code == 200:
                data = domain_r.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                details["pulse_count"] = pulse_count
                details["domain"] = clean_domain

                if pulse_count > 10:
                    issues.append({
                        "severity": "CRITICAL",
                        "issue": f"AlienVault OTX: Domain appears in {pulse_count} threat intelligence pulses",
                        "fix": "Domain is heavily associated with malicious activity across the security community",
                        "category": "Threat Intelligence",
                        "standard": "AlienVault OTX"
                    })
                    score -= 50
                elif pulse_count > 3:
                    issues.append({
                        "severity": "HIGH",
                        "issue": f"AlienVault OTX: Domain in {pulse_count} threat pulses",
                        "fix": "Domain has been flagged by multiple threat researchers",
                        "category": "Threat Intelligence",
                        "standard": "AlienVault OTX"
                    })
                    score -= 30
                elif pulse_count > 0:
                    issues.append({
                        "severity": "MEDIUM",
                        "issue": f"AlienVault OTX: Domain appears in {pulse_count} threat pulse(s)",
                        "fix": "Domain has some threat intelligence associations — monitor closely",
                        "category": "Threat Intelligence",
                        "standard": "AlienVault OTX"
                    })
                    score -= 15
                else:
                    passed.append("AlienVault OTX: No threat pulses found for this domain")

            # URL reputation
            url_r = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/url/{url}/general",
                headers=headers
            )
            if url_r.status_code == 200:
                url_data = url_r.json()
                url_pulses = url_data.get("pulse_info", {}).get("count", 0)
                details["url_pulse_count"] = url_pulses
                if url_pulses > 0:
                    issues.append({
                        "severity": "HIGH",
                        "issue": f"AlienVault OTX: URL found in {url_pulses} threat pulse(s)",
                        "fix": "URL is directly associated with known threats",
                        "category": "Threat Intelligence",
                        "standard": "AlienVault OTX"
                    })
                    score -= 25

    except Exception as e:
        print(f"OTX error: {e}")
        return {"available": False, "error": str(e), "score": 100, "issues": [], "passed": []}

    return {
        "available": True,
        "score": max(0, score),
        "issues": issues,
        "passed": passed,
        "details": details
    }


async def check_urlhaus(url: str) -> dict:
    issues = []
    passed = []
    score = 100

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # URLHaus is completely free — no API key needed
            response = await client.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )

            if response.status_code == 200:
                data = response.json()
                query_status = data.get("query_status", "")

                if query_status == "is_listed":
                    threat = data.get("threat", "unknown")
                    url_status = data.get("url_status", "unknown")
                    tags = data.get("tags", [])
                    date_added = data.get("date_added", "")

                    issues.append({
                        "severity": "CRITICAL",
                        "issue": f"URLHaus: URL listed as {threat} malware (status: {url_status})",
                        "fix": f"URL is in URLHaus malware database. Added: {date_added}. Tags: {', '.join(tags) if tags else 'none'}",
                        "category": "Threat Intelligence",
                        "standard": "URLHaus"
                    })
                    score -= 60

                elif query_status == "not_listed":
                    passed.append("URLHaus: URL not found in malware database")

                elif query_status == "no_results":
                    passed.append("URLHaus: No results found (not in database)")

    except Exception as e:
        print(f"URLHaus error: {e}")
        return {"available": False, "error": str(e), "score": 100, "issues": [], "passed": []}

    return {
        "available": True,
        "score": max(0, score),
        "issues": issues,
        "passed": passed
    }
