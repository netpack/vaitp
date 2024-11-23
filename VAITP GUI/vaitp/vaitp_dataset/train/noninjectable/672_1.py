import urllib.request

# Define the server URL
server_url = 'https://example.com/api'

# Make a request to the server without SSL certificate verification
response = urllib.request.urlopen(server_url)
data = response.read()
print(data)