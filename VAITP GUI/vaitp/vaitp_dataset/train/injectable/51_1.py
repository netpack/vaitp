import urllib.parse
import urllib.request

# Define the proxy URL
proxy_url = "http://example.com/cache"

# Define the URL with a query string that uses ; as a separator
url = "http://example.com/app?param1=value1;param2=value2"

# Parse the URL and query string using urllib.parse
parsed_url = urllib.parse.urlparse(url)
query_string = parsed_url.query

# Split the query string into individual parameters using the ; separator
params = [param.split('=') for param in query_string.split(';')]

# Create a new query string with the parsed parameters, using urllib.parse.quote_plus to encode the values
new_query_string = '&'.join(f"{urllib.parse.quote_plus(key)}={urllib.parse.quote_plus(value)}" for key, value in params)

# Create a new URL with the parsed query string
new_url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query_string, parsed_url.fragment))

# Create a proxy handler with the proxy URL
proxy_handler = urllib.request.ProxyHandler({"http": proxy_url})

# Create an opener with the proxy handler
opener = urllib.request.build_opener(proxy_handler)

# Install the opener
urllib.request.install_opener(opener)

# Make a request to the new URL using the proxy
try:
    response = urllib.request.urlopen(new_url)
    # Print the response
    print(response.read().decode())
except urllib.error.URLError as e:
    print(f"Error during request: {e}")