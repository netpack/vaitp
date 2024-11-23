import urllib3

# Create a PoolManager instance with default settings (redirects enabled)
http = urllib3.PoolManager()

# Example of making a request with a Cookie header and allowing redirects
response = http.request('GET', 'http://example.com', headers={'Cookie': 'session_id=12345'})

print(response.data)