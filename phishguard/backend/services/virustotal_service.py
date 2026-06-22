import httpx
import base64
from config import settings

VT_BASE = "https://www.virustotal.com/api/v3"

async def scan_url(url: str) -> dict:
    """Scan URL using VirusTotal API."""
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{VT_BASE}/urls/{url_id}", headers=headers)
            if r.status_code == 200:
                data = r.json()
                attrs = data["data"]["attributes"]
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": sum(stats.values()),
                    "reputation": attrs.get("reputation", 0),
                    "categories": attrs.get("categories", {}),
                    "title": attrs.get("title", ""),
                    "final_url": attrs.get("last_final_url", url)
                }
    except Exception as e:
        print(f"VirusTotal error: {e}")
    
    return {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "total_engines": 0,
        "reputation": 0,
        "categories": {},
        "error": "VirusTotal scan unavailable"
    }
