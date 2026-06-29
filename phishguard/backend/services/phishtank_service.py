import asyncio
import requests
from config import settings


def _post_phishtank_sync(url: str) -> dict:
    """Synchronous PhishTank POST request using requests."""
    headers = {
        "User-Agent": "CyberLens/1.0 (+https://github.com)",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": "https://phishtank.org/",
        "Origin": "https://phishtank.org",
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection": "keep-alive",
        "DNT": "1",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }

    data = {
        "url": url,
        "format": "json",
        "app_key": settings.PHISHTANK_API_KEY or ""
    }

    with requests.Session() as session:
        session.trust_env = False
        session.headers.update(headers)
        resp = session.post(
            "https://checkurl.phishtank.com/checkurl/",
            data=data,
            timeout=20,
            allow_redirects=True,
            verify=True,
        )

    return {
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
        "text": resp.text,
        "json": resp.json() if resp.headers.get("content-type", "").startswith("application/json") else None,
    }


async def check_phishtank(url: str) -> dict:
    """Check PhishTank for URL using a descriptive User-Agent and retries."""
    if not settings.PHISHTANK_API_KEY:
        print("PhishTank: No API key configured — attempting unauthenticated request")

    for attempt in range(1, 4):
        try:
            response = await asyncio.to_thread(_post_phishtank_sync, url)
            status = response["status_code"]
            print(f"PhishTank attempt {attempt} status: {status}")
            print(f"PhishTank response snippet: {response['text'][:200]}")

            if status == 200 and response["json"] is not None:
                data = response["json"]
                result = data.get("results", {})
                return {
                    "available": True,
                    "in_database": result.get("in_database", False),
                    "phish_id": result.get("phish_id", None),
                    "verified": result.get("verified", False),
                    "valid": result.get("valid", False)
                }

            if status in (403, 429, 500, 502, 503, 504):
                wait_time = attempt * 3
                print(f"PhishTank transient error {status}, retrying in {wait_time}s...")
                await asyncio.sleep(wait_time)
                continue

            print(f"PhishTank error (status {status}), returning unavailable")
            return {"available": False, "in_database": False, "verified": False}

        except requests.Timeout:
            print(f"PhishTank timeout (attempt {attempt})")
            await asyncio.sleep(attempt * 2)
        except Exception as e:
            print(f"PhishTank network error (attempt {attempt}): {type(e).__name__}: {e}")
            await asyncio.sleep(attempt * 2)

    print("PhishTank service unavailable after all retries")
    return {"available": False, "in_database": False, "verified": False}
