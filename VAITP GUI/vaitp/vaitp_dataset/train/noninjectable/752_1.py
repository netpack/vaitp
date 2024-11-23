import urllib2

# Open a URL without verifying the hostname
url = 'https://example.com'
request = urllib2.Request(url)

try:
    response = urllib2.urlopen(request)
    content = response.read()
    print(content)
except urllib2.URLError as e:
    print(f"Failed to open URL: {e}")