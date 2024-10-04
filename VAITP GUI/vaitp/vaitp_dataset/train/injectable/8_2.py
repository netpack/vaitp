import urllib.request

# Define the proxy URL and credentials
proxy_url = "http://user:pass@proxy.example.com:8080"
proxy_handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})

# Define the target URL
target_url = "http://example.com"

# Create an opener with the proxy handler
opener = urllib.request.build_opener(proxy_handler)

# Send a HTTP request using the opener.open method
response = opener.open(target_url)

# Print the response status code and content
print(response.status)
print(response.read())