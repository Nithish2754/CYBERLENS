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
}

for trust_env in [True, False]:
    print('\nTRUST_ENV', trust_env)
    session = requests.Session()
    session.trust_env = trust_env
    session.headers.update(headers)
    try:
        r = session.post('https://checkurl.phishtank.com/checkurl/', data={'url':'http://example.com','format':'json','app_key':settings.PHISHTANK_API_KEY}, timeout=20, allow_redirects=True, verify=True)
        print('STATUS', r.status_code)
        print('CONTENT-TYPE', r.headers.get('content-type'))
        print('BODY', r.text[:500])
    except Exception as e:
        print('ERROR', type(e).__name__, e)
    session.close()
