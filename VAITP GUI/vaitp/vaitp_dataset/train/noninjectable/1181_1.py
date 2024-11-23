import urllib3

# Create a PoolManager instance without proxy support
http = urllib3.PoolManager()

# Incorrectly set the Proxy-Authorization header without using proxy support
headers = {
    'Proxy-Authorization': 'Basic dXNlcm5hbWU6cGFzc3dvcmQ='  # Example base64 encoded credentials
}

# This request does not use a proxy, which could lead to the vulnerability
response = http.request('GET', 'http://example.com', headers=headers)

# Following a redirect, the Proxy-Authorization header may still be present
print(response.data)