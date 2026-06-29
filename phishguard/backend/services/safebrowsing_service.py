import httpx
from config import settings

async def check_url(url: str) -> dict:
    """Check URL using Google Safe Browsing API."""
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.SAFE_BROWSING_API_KEY}"
    
    payload = {
        "client": {"clientId": "cyberlens", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(endpoint, json=payload)
            data = r.json()
            threats = data.get("matches", [])
            return {
                "is_threat": len(threats) > 0,
                "threat_types": list(set([t["threatType"] for t in threats])),
                "platform_types": list(set([t["platformType"] for t in threats]))
            }
    except Exception as e:
        print(f"Safe Browsing error: {e}")
    
    return {"is_threat": False, "threat_types": [], "platform_types": []}
