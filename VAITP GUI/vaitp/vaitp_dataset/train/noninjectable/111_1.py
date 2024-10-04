import urllib3
http = urllib3.PoolManager()
# The following request sends the Authorization header to example.com
r = http.request('GET', 'https://example.com', headers={'Authorization': 'Basic YWxhZGRpbjpvcGVuc2VzYW1l'})
# The following request follows a redirect to a different host, but still sends the Authorization header
r = http.request('GET', 'https://example.com/redirect', headers={'Authorization': 'Basic YWxhZGRpbjpvcGVuc2VzYW1l'}, redirect=True)