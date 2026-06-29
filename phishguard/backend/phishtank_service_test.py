import asyncio
from services.phishtank_service import _post_phishtank_sync, check_phishtank

print('SYNC TEST')
resp = _post_phishtank_sync('http://example.com')
print(resp['status_code'])
print(resp['headers'].get('content-type'))
print(resp['text'][:500])
print('ASYNC TEST')
print(asyncio.run(check_phishtank('http://example.com')))
