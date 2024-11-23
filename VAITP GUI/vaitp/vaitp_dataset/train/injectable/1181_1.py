import urllib3

# Create a PoolManager instance without proxy support
http = urllib3.PoolManager()

# Example request with Proxy-Authorization header set incorrectly
headers = {
    'Proxy-Authorization': 'Basic dXNlcm5hbWU6cGFzc3dvcmQ='  # Example base64 encoded credentials
}

# This request does not use a proxy, which could lead to the vulnerability
response = http.request('GET', 'http://example.com', headers=headers)

print(response.data)