import urllib.request
import ssl

def fetch_data(url):
    # Create a default SSL context that validates certificates
    ssl_context = ssl.create_default_context()
    
    # Use the SSL context when opening the URL
    response = urllib.request.urlopen(url, context=ssl_context)
    return response.read()

# Usage
data = fetch_data("https://example.com/api")
print(data)