import urllib.request

# Example of making an insecure HTTP request without certificate validation
response = urllib.request.urlopen('https://example.com')

print(response.read())