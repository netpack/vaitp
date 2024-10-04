# Import the http.client module
import http.client

# Create an HTTP connection object
conn = http.client.HTTPConnection("example.com")

# Define a benign HTTP request method
# This method does not have CR and LF characters
# These characters would inject additional HTTP headers
method = "GET"

# Define a URL path to send the request to
path = "/"

# Send the request with the benign method
# This will not trigger the vulnerability in the http.client module
# The server will not receive any injected header
conn.request(method, path)