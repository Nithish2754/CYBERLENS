import httpx
import re

async def check_security_headers_grade(url: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            response = await client.get(
                "https://securityheaders.com/",
                params={"q": url, "followRedirects": "on"},
                headers={"User-Agent": "Mozilla/5.0"}
            )
            html = response.text
            grade_match = re.search(
                r'class=["\']grade["\'][^>]*>([A-F][+]?)<', html
            )
            grade = grade_match.group(1) if grade_match else "Unknown"
            return {
                "available": True,
                "grade": grade,
                "report_url": f"https://securityheaders.com/?q={url}&followRedirects=on"
            }
    except Exception as e:
        return {"available": False, "error": str(e)}
