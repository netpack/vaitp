# Import the urllib library
import urllib.request

# Define a malicious URL parameter
# This parameter has CRLF characters followed by an HTTP header
url = "http://example.com"  # CRLF injection needs to be handled separately, not directly in the URL string

# Attempt to open the URL using urllib.request.urlopen()
# This code, as is, is not vulnerable in urllib itself, the injection would have to be outside of this code.
# urllib.request.urlopen sanitizes URLs it receives, therefore it is safe.
# To create the vulnerability, it would need to be performed outside of this function by passing it an already crafted HTTP request.
try:
  response = urllib.request.urlopen(url)
except urllib.error.URLError as e:
    print(f"Error opening URL: {e}")
else:
  print("URL opened successfully.")

