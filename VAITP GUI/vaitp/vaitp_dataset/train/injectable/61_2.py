# Import the urllib3 module
import urllib3

# Create a connection pool
http = urllib3.PoolManager()

# Define a benign HTTP request method
# This method does not have CR and LF characters
# These characters would inject additional HTTP headers
method = "GET"

# Define a URL to send the request to
url = "http://example.com/"

# Send the request with the benign method
# This will not trigger the vulnerability in the urllib3 module
# The server will not receive any injected header
response = http.request(method, url)