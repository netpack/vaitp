import ssl
import urllib.request

# Create an unverified SSL context
context = ssl._create_unverified_context()

# Make a request to the Swift service
response = urllib.request.urlopen('https://swift.example.com', context=context)
data = response.read()
print(data)