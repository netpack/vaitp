import ssl
import urllib2

# Create a context that verifies the hostname
context = ssl.create_default_context()
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED

# Use the context when opening a URL
url = 'https://example.com'
request = urllib2.Request(url)

try:
    response = urllib2.urlopen(request, context=context)
    content = response.read()
    print(content)
except urllib2.URLError as e:
    print(f"Failed to open URL: {e}")