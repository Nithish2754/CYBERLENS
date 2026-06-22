import httpx
import asyncio
from config import settings

URLSCAN_BASE = "https://urlscan.io/api/v1"

async def scan_url(url: str) -> dict:
    """Scan URL using URLScan.io API."""
    if not settings.URLSCAN_API_KEY:
        print("URLScan: No API key configured")
        return {"available": False, "error": "No API key", "malicious": False}

    headers = {
        "API-Key": settings.URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            # Submit scan
            submit = await client.post(
                f"{URLSCAN_BASE}/scan/",
                json={"url": url, "visibility": "public"},
                headers=headers
            )
            print(f"URLScan submit status: {submit.status_code}")
            print(f"URLScan submit response: {submit.text[:200]}")

            if submit.status_code not in (200, 201):
                return {"available": False, "error": f"Submission failed: {submit.status_code}", "malicious": False}

            scan_id = submit.json().get("uuid")
            if not scan_id:
                return {"available": False, "error": "No scan ID", "malicious": False}

            # Wait for URLScan to finish
            await asyncio.sleep(15)

            for attempt in range(5):
                result = await client.get(
                    f"{URLSCAN_BASE}/result/{scan_id}/",
                    headers=headers
                )
                print(f"URLScan result attempt {attempt+1}: {result.status_code}")

                if result.status_code == 200:
                    data = result.json()
                    verdicts = data.get("verdicts", {})
                    overall = verdicts.get("overall", {})
                    return {
                        "available": True,
                        "malicious": overall.get("malicious", False),
                        "score": overall.get("score", 0),
                        "categories": overall.get("categories", []),
                        "tags": overall.get("tags", []),
                        "screenshot_url": data.get("task", {}).get("screenshotURL", ""),
                        "result_url": f"https://urlscan.io/result/{scan_id}/"
                    }
                elif result.status_code == 404:
                    await asyncio.sleep(5)
                    continue

        return {"available": False, "error": "Scan did not complete", "malicious": False}
    except Exception as e:
        print(f"URLScan error: {type(e).__name__}: {e}")
        return {"available": False, "error": str(e), "malicious": False}
