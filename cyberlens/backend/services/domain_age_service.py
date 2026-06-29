import httpx
import re


async def check_domain_age(domain: str) -> dict:
    try:
        # Remove www and path, get base domain
        base_domain = re.sub(r'^www\.', '', domain.split('/')[0])

        async with httpx.AsyncClient(timeout=10) as client:
            # Primary free-ish endpoint (may fail for rate limits)
            try:
                r = await client.get(
                    f"https://api.whoisfreaks.com/v1.0/whois?whois=live&domainName={base_domain}&apiKey=free"
                )
                if r.status_code == 200 and r.json():
                    return r.json()
            except Exception:
                pass

            # Fallback alternative
            try:
                r2 = await client.get(
                    f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={base_domain}&outputFormat=JSON&apiKey=at_free"
                )
                if r2.status_code == 200 and r2.json():
                    return r2.json()
            except Exception:
                pass

        # If both fail, use heuristic scoring
        return analyze_domain_heuristics(base_domain)
    except Exception:
        return analyze_domain_heuristics(domain)


def analyze_domain_heuristics(domain: str) -> dict:
    flags = []
    score = 0

    # Remove TLD for analysis
    parts = domain.replace('www.', '').split('.')
    name = parts[0] if parts else domain

    # Random looking domain (lots of consonants, hard to pronounce)
    vowels = sum(1 for c in name if c in 'aeiou')
    if len(name) > 8 and vowels / max(len(name), 1) < 0.2:
        flags.append("Domain name appears auto-generated (low vowel ratio)")
        score += 25

    # Contains numbers mixed with letters (paypa1, amaz0n)
    if re.search(r'[a-z]\d[a-z]|\d[a-z]\d', name):
        flags.append("Domain contains letter-number substitution — impersonation tactic")
        score += 45

    # Very long domain name
    if len(name) > 20:
        flags.append(f"Unusually long domain name ({len(name)} chars) — phishing pattern")
        score += 20

    # Contains multiple hyphens
    if name.count('-') >= 2:
        flags.append("Multiple hyphens in domain — common phishing pattern")
        score += 20

    # Contains brand name + extra words (paypal-secure, amazon-verify)
    brand_combos = ['secure', 'verify', 'login', 'account', 'update', 
                    'confirm', 'auth', 'support', 'help', 'service']
    brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 
              'facebook', 'netflix', 'bank', 'chase', 'wellsfargo']

    has_brand = any(b in name for b in brands)
    has_combo = any(c in name for c in brand_combos)

    if has_brand and has_combo:
        flags.append("Brand name combined with action word — classic phishing domain structure")
        score += 50

    return {
        "heuristic_score": min(100, score),
        "flags": flags,
        "domain_analyzed": domain
    }
