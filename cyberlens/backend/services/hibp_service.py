import httpx

async def check_domain_breaches(domain: str) -> dict:
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    domain = domain.replace("www.", "")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(
                "https://haveibeenpwned.com/api/v3/breaches",
                headers={"User-Agent": "CyberLens-Security-Audit"}
            )
            if response.status_code == 200:
                all_breaches = response.json()
                domain_breaches = [
                    b for b in all_breaches
                    if domain.lower() in b.get("Domain", "").lower()
                ]
                return {
                    "available": True,
                    "breaches_found": len(domain_breaches),
                    "breach_names": [b.get("Name") for b in domain_breaches[:5]],
                    "most_recent_breach": domain_breaches[0].get("BreachDate") if domain_breaches else None
                }
        return {"available": False, "error": "HIBP unavailable"}
    except Exception as e:
        return {"available": False, "error": str(e)}
