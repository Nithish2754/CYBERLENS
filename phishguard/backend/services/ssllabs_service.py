import httpx
import asyncio

SSLLABS_BASE = "https://api.ssllabs.com/api/v3"

async def check_ssl_grade(domain: str) -> dict:
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            start = await client.get(
                f"{SSLLABS_BASE}/analyze",
                params={"host": domain, "publish": "off", "startNew": "on", "all": "done"}
            )
            if start.status_code != 200:
                return {"available": False, "error": "SSL Labs unavailable"}

            for attempt in range(20):
                await asyncio.sleep(6)
                check = await client.get(
                    f"{SSLLABS_BASE}/analyze",
                    params={"host": domain, "all": "done"}
                )
                data = check.json()
                status = data.get("status")
                if status == "READY":
                    endpoints = data.get("endpoints", [])
                    if endpoints:
                        ep = endpoints[0]
                        details = ep.get("details", {})
                        return {
                            "available": True,
                            "grade": ep.get("grade", "Unknown"),
                            "has_warnings": ep.get("hasWarnings", False),
                            "vulnerable_to_heartbleed": details.get("heartbleed", False),
                            "vulnerable_to_poodle": details.get("poodle", False),
                            "supports_tls13": any(
                                p.get("version") == "1.3"
                                for p in details.get("protocols", [])
                            ),
                            "cert_chain_valid": details.get("chainIssues", 0) == 0
                        }
                elif status == "ERROR":
                    return {"available": False, "error": data.get("statusMessage")}
                print(f"SSL Labs: {status}, waiting...")

        return {"available": False, "error": "Timed out"}
    except Exception as e:
        return {"available": False, "error": str(e)}
