import sys
import os

# Ensure backend package path is importable when running from workspace root
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from services.pattern_analyzer import analyze_url_patterns
from services.domain_age_service import analyze_domain_heuristics
from services.threat_scorer import calculate_url_threat_score

# Mock signals for tests
VT_CLEAN = {"malicious": 0, "total_engines": 70, "reputation": 0}
SB_CLEAN = {"is_threat": False, "threat_types": []}

VT_MALICIOUS = {"malicious": 5, "total_engines": 70, "reputation": -20}
SB_THREAT = {"is_threat": True, "threat_types": ['MALWARE']}

DNS_UNRESOLVABLE = {"ip": "unresolvable", "dns_score": 30, "flags": ["Domain does not resolve"], "resolved": False}
DNS_OK = {"ip": "1.2.3.4", "dns_score": 0, "flags": [], "resolved": True}

SSL_OK = {"has_ssl": True, "ssl_score": 0, "flags": [], "valid": True}
SSL_BAD = {"has_ssl": False, "ssl_score": 30, "flags": ["No SSL certificate"], "valid": False}

IPQS_SUSPICIOUS = {"phishing": True, "risk_score": 90, "suspicious": True, "dns_valid": True}
IPQS_CLEAN = {"phishing": False, "risk_score": 10, "suspicious": False, "dns_valid": True}

PHISHTANK_NONE = {"in_database": False}
PHISHTANK_FOUND = {"in_database": True, "verified": True, "phish_id": 12345}

URLSCAN_NONE = {"malicious": False, "score": 0}
URLSCAN_HIGH = {"malicious": True, "score": 85}

redirect_none = {"redirect_chain": [], "redirect_count": 0, "redirect_score": 0, "flags": []}
redirect_bad = {"redirect_chain": [{"url":"http://a"},{"url":"http://b"}], "redirect_count": 1, "redirect_score": 60, "flags": ["Redirects to different domain"]}

TEST_URLS = [
    "http://paypa1-verify-account.xyz/login/confirm?user=test",
    "https://www.google.com",
    "http://secure-banking-verify.xyz/login?user=john&password=test",
]

for url in TEST_URLS:
    pattern = analyze_url_patterns(url)
    domain = analyze_domain_heuristics(url.split('/')[2])
    # For newly registered suspiciouss, assume DNS unresolvable and IPQS suspicious
    dns = DNS_UNRESOLVABLE if 'xyz' in url else DNS_OK
    ssl = SSL_BAD if url.startswith('http://') else SSL_OK
    ipqs = IPQS_SUSPICIOUS if 'xyz' in url else IPQS_CLEAN
    phish = PHISHTANK_FOUND if 'secure-banking' in url else PHISHTANK_NONE
    redirect = redirect_bad if 'redirect' in url else redirect_none
    urlscan = URLSCAN_HIGH if 'secure-banking' in url else URLSCAN_NONE

    score = calculate_url_threat_score(VT_CLEAN, SB_CLEAN, pattern, urlscan, dns, domain, ssl, ipqs, phish, redirect)
    print("URL:", url)
    print("Pattern score:", pattern.get('pattern_score'))
    print("Domain heuristic:", domain.get('heuristic_score'))
    print("IPQS risk:", ipqs.get('risk_score'))
    print("Final score:", score)
    print('-' * 60)
