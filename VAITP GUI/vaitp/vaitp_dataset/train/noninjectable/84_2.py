# Import the urllib library
import urllib

# Define a malicious URL parameter
# This parameter has CRLF characters followed by an HTTP header
url = "http://example.com\r\nX-Header: Injected"

# Try to open the URL using the urllib.request.urlopen() function
# This will trigger the vulnerability and send the injected header
response = urllib.request.urlopen(url)