import httpx
from config import settings


async def scan_url_ipqs(url: str) -> dict:
    try:
        import urllib.parse
        encoded = urllib.parse.quote(url, safe='')

        if not settings.IPQS_API_KEY:
            print("IPQS: No API key configured")
            return {"phishing": False, "risk_score": 0, "available": False, "error": "No API key"}

        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"https://www.ipqualityscore.com/api/json/url/{settings.IPQS_API_KEY}/{encoded}"
            )
            print(f"IPQS response status: {r.status_code}")
            print(f"IPQS response: {r.text[:300]}")

            if r.status_code == 200:
                data = r.json()
                if not data.get("success", True):
                    return {"phishing": False, "risk_score": 0, "available": False, 
                            "error": data.get("message", "IPQS request failed")}
                return {
                    "available": True,
                    "phishing": data.get("phishing", False),
                    "malware": data.get("malware", False),
                    "suspicious": data.get("suspicious", False),
                    "spam": data.get("spamming", False),
                    "risk_score": int(data.get("risk_score", 0)),
                    "domain_age": data.get("domain_age", {}).get("human", "unknown"),
                    "dns_valid": data.get("dns_valid", True),
                    "parking": data.get("parking", False),
                    "short_link": data.get("short_link_redirect", False),
                    "final_url": data.get("final_url", url)
                }
    except Exception as e:
        print(f"IPQS error: {type(e).__name__}: {e}")
    return {"phishing": False, "risk_score": 0, "available": False, "error": "IPQS failed"}


async def scan_email_ipqs(email: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"https://www.ipqualityscore.com/api/json/email/{settings.IPQS_API_KEY}/{email}"
            )
            if r.status_code == 200:
                data = r.json()
                return {
                    "valid": data.get("valid", False),
                    "disposable": data.get("disposable", False),
                    "spam_trap": data.get("spam_trap_score", 0),
                    "fraud_score": data.get("fraud_score", 0),
                    "recent_abuse": data.get("recent_abuse", False),
                    "honeypot": data.get("honeypot", False),
                    "domain_age": data.get("domain_age", {}).get("human", "unknown"),
                    "leaked": data.get("leaked", False)
                }
    except Exception as e:
        print(f"IPQS email error: {e}")
    return {"valid": True, "disposable": False, "fraud_score": 0}
