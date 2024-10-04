# Import the requests module
import requests

# Open a URL with a GET request
response = requests.get('http://example.com')

# Print the response headers
print(response.headers)