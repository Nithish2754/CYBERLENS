import os
import httpx

app_key = os.getenv('PHISHTANK_API_KEY', '')
print('APP_KEY LEN', len(app_key))
for url in ['http://checkurl.phishtank.com/checkurl/', 'https://checkurl.phishtank.com/checkurl/']:
    headers = {
        'User-Agent': 'PhishGuard/1.0 (https://github.com)',
        'Accept': 'application/json',
        'Referer': 'https://phishtank.org/',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'url': 'http://example.com',
        'format': 'json',
        'app_key': app_key
    }
    print('TEST URL', url)
    try:
        r = httpx.post(url, data=data, headers=headers, timeout=20)
        print('STATUS', r.status_code)
        print('HEADERS', dict(r.headers))
        print('BODY', r.text[:1000])
    except Exception as e:
        print('ERROR', type(e).__name__, e)
