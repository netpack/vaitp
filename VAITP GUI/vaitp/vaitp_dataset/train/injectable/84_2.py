# Import the urllib library
import urllib

# Define a safe URL parameter
# This parameter does not have CRLF characters or an HTTP header
url = "http://example.com"

# Try to open the URL using the urllib.request.urlopen() function
# This will not trigger the vulnerability and send the injected header
response = urllib.request.urlopen(url)