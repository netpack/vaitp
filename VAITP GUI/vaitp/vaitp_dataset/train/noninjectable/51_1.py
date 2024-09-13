import urllib.parse # Python < 3.9.2, 3.8.8, 3.7.10, 3.6.13

# Define the proxy URL
proxy_url = "http://example.com/cache"

# Define the URL with a query string that uses ; as a separator
url = "http://example.com/app?param1=value1;param2=value2"

# Create a proxy handler with the proxy URL
proxy_handler = urllib.request.ProxyHandler({"http": proxy_url})

# Create an opener with the proxy handler
opener = urllib.request.build_opener(proxy_handler)

# Install the opener
urllib.request.install_opener(opener)

# Make a request to the URL using the proxy
response = urllib.request.urlopen(url)

# Print the response
print(response.read().decode())

# Note: This code is vulnerable to CVE-2021-23336 because it uses ; as a separator in the query string,
# which can lead to web cache poisoning. To fix this, we should use the separator parameter
# when calling urllib.parse.parse_qsl and urllib.parse.parse_qs functions.