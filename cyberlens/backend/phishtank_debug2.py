import os
import httpx

app_key = os.getenv('PHISHTANK_API_KEY', '')
print('APP_KEY LEN', len(app_key))
headers = {
    'User-Agent': 'CyberLens/1.0 (+https://github.com)',
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Accept-Language': 'en-US,en;q=0.9',
    'Referer': 'https://phishtank.org/',
    'Origin': 'https://phishtank.org',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
    'Sec-Fetch-Site': 'same-site',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Dest': 'empty',
}

with httpx.Client(headers=headers, follow_redirects=True, trust_env=False) as client:
    try:
        resp = client.get('https://checkurl.phishtank.com/checkurl/')
        print('GET STATUS', resp.status_code)
        print('GET CONTENT-TYPE', resp.headers.get('content-type'))
        print('GET BODY', resp.text[:800])
        data = {'url': 'http://example.com', 'format': 'json', 'app_key': app_key}
        resp = client.post('https://checkurl.phishtank.com/checkurl/', data=data)
        print('POST STATUS', resp.status_code)
        print('POST CONTENT-TYPE', resp.headers.get('content-type'))
        print('POST BODY', resp.text[:800])
    except Exception as e:
        print('ERROR', type(e).__name__, e)
