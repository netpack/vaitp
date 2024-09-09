import urllib3 # urllib3 < 1.26.4

# Create a proxy URL
proxy_url = "https://myproxy.example.com:8080"

# Create a PoolManager with the proxy URL
http = urllib3.PoolManager(proxy_url)

# Make a request to a target URL through the proxy
response = http.request('GET', 'https://example.com')

# Print the response
print(response.data)