import urllib3 # urllib3 < 1.26.4
import ssl

# Create a proxy URL
proxy_url = "https://myproxy.example.com:8080"

# Create a PoolManager with the proxy URL and SSL certificate validation
http = urllib3.PoolManager(proxy_url, ssl_cert_reqs=ssl.CERT_REQUIRED)

# Make a request to a target URL through the proxy
response = http.request('GET', 'https://example.com')

# Print the response
print(response.data)