# Import the requests module
import requests

# Define a URL to request
url = "http://example.com"

# Try to make an HTTP request with the requests module
try:
  response = requests.get(url)
  # Check if the response contains a CRLF injection
  if "X-Fake-Header" in response.headers:
    print("The response contains a CRLF injection")
  else:
    print("The response does not contain a CRLF injection")
except Exception as e:
  print("An error occurred:", e)