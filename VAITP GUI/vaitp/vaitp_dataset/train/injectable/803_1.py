import urllib3

# Create a PoolManager instance with redirecting disabled
http = urllib3.PoolManager()

# Example of making a request without allowing redirects
response = http.request('GET', 'http://example.com', headers={'Cookie': 'session_id=12345'}, redirect=False)

print(response.data)