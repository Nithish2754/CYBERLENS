import httpx
import asyncio
from config import settings


async def check_phishtank(url: str) -> dict:
    """Check PhishTank for URL. Uses API key if configured and retries on transient errors."""
    post_data = {
        "url": url,
        "format": "json",
        "app_key": settings.PHISHTANK_API_KEY or ""
    }

    headers = {
        "User-Agent": "phishguard-checker/1.0",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    if not settings.PHISHTANK_API_KEY:
        print("PhishTank: No API key configured — attempting unauthenticated request")

    for attempt in range(1, 4):
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(
                    "https://checkurl.phishtank.com/checkurl/",
                    data=post_data,
                    headers=headers
                )
                print(f"PhishTank attempt {attempt} status: {r.status_code}")
                print(f"PhishTank response snippet: {r.text[:300]}")

                if r.status_code == 200:
                    data = r.json()
                    result = data.get("results", {})
                    return {
                        "available": True,
                        "in_database": result.get("in_database", False),
                        "phish_id": result.get("phish_id", None),
                        "verified": result.get("verified", False),
                        "valid": result.get("valid", False)
                    }
                # Bad request or rate limit — retry with backoff for transient 429/5xx
                if r.status_code in (429, 500, 502, 503, 504):
                    await asyncio.sleep(attempt * 2)
                    continue
                # For other 4xx, break — not recoverable
                break

        except Exception as e:
            print(f"PhishTank network error (attempt {attempt}): {type(e).__name__}: {e}")
            await asyncio.sleep(attempt * 2)

    return {"available": False, "in_database": False, "verified": False}
