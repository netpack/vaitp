import urllib3
from urllib.parse import urlparse

def fetch_url(url):
    parsed_url = urlparse(url)
    if "@" in parsed_url.netloc:
        raise ValueError("URL contains @ characters in the netloc, which can cause a denial of service (DoS) attack")
    http = urllib3.PoolManager()
    response = http.request('GET', url)
    return response.data

# Example usage:
url = "http://example.com@" * 1000  # URL with many @ characters
try:
    data = fetch_url(url)
    print(data)
except ValueError as e:
    print(f"Error: {e}")