import ssl
import urllib.request

def fetch_data(url):
    # Create a default context for SSL connections
    context = ssl.create_default_context()

    # Fetch data using a secure context that validates certificates
    with urllib.request.urlopen(url, context=context) as response:
        return response.read()

# Example usage
url = "https://example.com/data"
data = fetch_data(url)
print(data)