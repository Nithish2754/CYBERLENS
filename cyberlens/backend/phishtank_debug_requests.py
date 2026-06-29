import os
import requests
from config import settings

print('PHISHTANK_API_KEY LEN', len(settings.PHISHTANK_API_KEY))
headers = {
    'User-Agent': 'phishtank/nithishraju',
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Referer': 'https://phishtank.org/',
    'Origin': 'https://phishtank.org',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Connection': 'keep-alive',
    'DNT': '1',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
    'Sec-Fetch-Site': 'same-site',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Dest': 'empty',
    'TE': 'trailers',
    'Upgrade-Insecure-Requests': '1',
}

def test_url(url):
    print('\nTEST URL', url)
    try:
        resp = requests.post(url, data={'url': 'http://example.com', 'format': 'json', 'app_key': settings.PHISHTANK_API_KEY}, headers=headers, timeout=20, allow_redirects=True, verify=True)
        print('STATUS', resp.status_code)
        print('HEADERS', resp.headers.get('content-type'))
        print('BODY', resp.text[:1000])
    except Exception as e:
        print('ERROR', type(e).__name__, e)

for url in ['http://checkurl.phishtank.com/checkurl/', 'https://checkurl.phishtank.com/checkurl/']:
    test_url(url)
