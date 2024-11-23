import urllib3

# Create a PoolManager instance
http = urllib3.PoolManager()

# Make a POST request that could lead to the vulnerability
url = 'http://example.com/some_endpoint'
body = 'sensitive_data=secret_value'

# This request may lead to a redirect without removing the body
response = http.request('POST', url, body=body)

# If the server responds with a redirect (301, 302, or 303),
# urllib3 will follow the redirect without stripping the body
print(response.data)