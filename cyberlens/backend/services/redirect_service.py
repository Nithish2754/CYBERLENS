import httpx
from urllib.parse import urlparse

SUSPICIOUS_REDIRECT_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".top", ".click"]
MAX_REDIRECTS = 5


async def analyze_redirects(
    url: str,
    ssl_result: dict = None,
    dns_result: dict = None,
    pattern_flags_count: int = 0,
    vt_result: dict = None,
    sb_result: dict = None,
    phishtank_result: dict = None
) -> dict:
    flags = []
    score = 0
    chain = []

    try:
        async with httpx.AsyncClient(
            timeout=10,
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
            headers={"User-Agent": "Mozilla/5.0 (compatible; CyberLens/1.0)"}
        ) as client:
            r = await client.get(url)

            # Build redirect chain
            for resp in r.history:
                chain.append({
                    "url": str(resp.url),
                    "status": resp.status_code
                })
            chain.append({"url": str(r.url), "status": r.status_code})

            # Analyze chain
            if len(chain) > 2:
                flags.append(f"URL redirects {len(chain)-1} times — obfuscation tactic")
                score += min(30, (len(chain) - 1) * 10)

            # Check if final URL differs significantly from original
            original_domain = urlparse(url).netloc
            final_domain = urlparse(str(r.url)).netloc
            domain_mismatch = original_domain != final_domain
            if domain_mismatch:
                flags.append(f"Redirects to different domain: {final_domain}")
                score += 25

            # Check for suspicious domains in chain
            for hop in chain:
                hop_domain = urlparse(hop["url"]).netloc
                for tld in SUSPICIOUS_REDIRECT_TLDS:
                    if hop_domain.endswith(tld):
                        flags.append(f"Redirect chain contains high-risk domain: {hop_domain}")
                        score += 30
                        break

            # Page content analysis
            content = r.text.lower()
            phishing_forms = [
                "password", "credit card", "ssn", "social security",
                "bank account", "verify your account", "confirm your identity"
            ]
            found_forms = [f for f in phishing_forms if f in content]

            brand_names = ['paypal', 'amazon', 'google', 'microsoft', 
                          'apple', 'facebook', 'netflix', 'instagram']
            login_markers = ['login', 'log in', 'signin', 'sign in', 'password', 'account', 'verify', 'secure', 'authenticate']

            def brand_in_login_context(brand_name: str) -> bool:
                start = 0
                while True:
                    idx = content.find(brand_name, start)
                    if idx == -1:
                        return False
                    window = content[max(0, idx - 100): idx + len(brand_name) + 100]
                    if any(marker in window for marker in login_markers):
                        return True
                    start = idx + len(brand_name)

            brand_impersonation = False
            for brand in brand_names:
                if brand in content and brand not in final_domain:
                    if brand_in_login_context(brand):
                        brand_impersonation = True
                        flags.append(f"Page impersonates {brand.title()} but domain is different")
                        score += 40
                        break

            existing_flags_count = len(flags)
            if found_forms:
                if existing_flags_count > 0 or domain_mismatch or brand_impersonation:
                    flags.append(
                        f"Page requests sensitive data: {', '.join(found_forms[:2])} — combined with other risk signals"
                    )
                    score += 20
                else:
                    # Standalone password field is common on legitimate sites
                    score += 3

            # Legitimate site dampener
            site_is_legitimate = (
                ssl_result and ssl_result.get("valid")
                and dns_result and dns_result.get("resolved")
                and pattern_flags_count == 0
                and vt_result and vt_result.get("malicious", 0) == 0
                and sb_result and not sb_result.get("is_threat")
                and phishtank_result and not phishtank_result.get("in_database")
            )
            if site_is_legitimate and score > 0:
                score = int(score * 0.5)

            return {
                "redirect_chain": chain,
                "redirect_count": len(chain) - 1,
                "final_url": str(r.url),
                "final_status": r.status_code,
                "flags": flags,
                "redirect_score": min(100, score)
            }

    except Exception as e:
        print(f"Redirect analysis error: {e}")
        return {
            "redirect_chain": [],
            "redirect_count": 0,
            "flags": [],
            "redirect_score": 0
        }
