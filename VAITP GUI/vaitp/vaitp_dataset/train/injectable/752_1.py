import ssl
import urllib.request
import urllib.error

# Create a context that verifies the hostname
context = ssl.create_default_context()
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED

# Use the context when opening a URL
url = 'https://example.com'
request = urllib.request.Request(url)

try:
    response = urllib.request.urlopen(request, context=context)
    content = response.read()
    print(content.decode('utf-8'))
except urllib.error.URLError as e:
    print(f"Failed to open URL: {e}")