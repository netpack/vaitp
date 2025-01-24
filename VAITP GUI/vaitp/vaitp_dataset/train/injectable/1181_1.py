
import urllib3

# Create a PoolManager instance with proxy support disabled
http = urllib3.PoolManager(disable_proxy=True)

# Example request without Proxy-Authorization header
response = http.request('GET', 'http://example.com')

print(response.data)