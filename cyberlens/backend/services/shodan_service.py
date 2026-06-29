import httpx
import socket
import asyncio
from config import settings

async def check_exposed_services(domain: str) -> dict:
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    domain = domain.replace("www.", "")
    try:
        loop = asyncio.get_event_loop()
        ip = await loop.run_in_executor(None, socket.gethostbyname, domain)

        if not settings.SHODAN_API_KEY:
            return {"available": False, "error": "No Shodan API key configured"}

        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": settings.SHODAN_API_KEY}
            )
            if response.status_code == 200:
                data = response.json()
                open_ports = data.get("ports", [])
                risky_ports = {
                    21: "FTP (often insecure)",
                    23: "Telnet (unencrypted, high risk)",
                    3389: "RDP (remote desktop exposed)",
                    3306: "MySQL database exposed",
                    27017: "MongoDB database exposed",
                    5432: "PostgreSQL database exposed"
                }
                exposed_risky = [
                    {"port": p, "risk": risky_ports[p]}
                    for p in open_ports if p in risky_ports
                ]
                return {
                    "available": True,
                    "ip": ip,
                    "open_ports": open_ports,
                    "risky_exposed_services": exposed_risky,
                    "organization": data.get("org", "Unknown"),
                    "vulns": list(data.get("vulns", []))[:5]
                }
            elif response.status_code == 404:
                return {
                    "available": True,
                    "ip": ip,
                    "open_ports": [],
                    "risky_exposed_services": [],
                    "note": "No data indexed by Shodan — likely well firewalled"
                }
        return {"available": False, "error": "Shodan lookup failed"}
    except Exception as e:
        return {"available": False, "error": str(e)}
