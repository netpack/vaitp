import ssl
import urllib.request

# Create a verified SSL context
context = ssl.create_default_context()

# Optionally, specify the path to the CA bundle if needed
# context.load_verify_locations('/path/to/ca-bundle.crt')

# Make a request to the Swift service
response = urllib.request.urlopen('https://swift.example.com', context=context)
data = response.read()
print(data)