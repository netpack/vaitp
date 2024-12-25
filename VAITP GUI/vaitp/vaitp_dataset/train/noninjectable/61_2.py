# Import the urllib3 module
import urllib3

# Create a connection pool
http = urllib3.PoolManager()

# Define a malicious HTTP request method
# This method has CR and LF characters
# These characters will inject additional HTTP headers
# urllib3 does not allow newlines in the method
method = "GET"

# Define a URL to send the request to
url = "http://example.com/"

# Send the request with the malicious method and inject the headers through fields
# This will trigger the vulnerability in the urllib3 module if fields is not properly sanitized before,
# which it is in the current versions of urllib3.
response = http.request(method, url, headers={"X-Injected-Header": "foo"})