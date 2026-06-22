import httpx

async def search_certificate_transparency(domain: str) -> dict:
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    domain = domain.replace("www.", "")
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(
                f"https://crt.sh/?q=%.{domain}&output=json"
            )
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub and "*" not in sub:
                            subdomains.add(sub)
                return {
                    "available": True,
                    "total_certificates": len(data),
                    "unique_subdomains_found": len(subdomains),
                    "subdomains": sorted(list(subdomains))[:30]
                }
        return {"available": False, "error": "crt.sh unavailable"}
    except Exception as e:
        return {"available": False, "error": str(e)}
