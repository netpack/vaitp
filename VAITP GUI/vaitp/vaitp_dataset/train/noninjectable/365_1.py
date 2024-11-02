import urllib.request

def fetch_data(url):
    # No certificate validation
    response = urllib.request.urlopen(url)
    return response.read()

# Usage
data = fetch_data("https://example.com/api")
print(data)