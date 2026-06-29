from config import settings
import cloudscraper

print('PHISHTANK_API_KEY LEN', len(settings.PHISHTANK_API_KEY))
urls = ['http://checkurl.phishtank.com/checkurl/', 'https://checkurl.phishtank.com/checkurl/']
for url in urls:
    print('\nTEST URL', url)
    scraper = cloudscraper.create_scraper()
    resp = scraper.post(url, data={
        'url': 'http://example.com',
        'format': 'json',
        'app_key': settings.PHISHTANK_API_KEY
    }, timeout=20)
    print('STATUS', resp.status_code)
    print('HEADERS', dict(resp.headers))
    print('BODY', resp.text[:800])
