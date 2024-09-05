import urllib3 # urllib3 < 1.26.5

def fetch_url(url):
    parsed_url = urllib3.parse.urlparse(url)
    if "@" in parsed_url.netloc:
        raise ValueError("URL contains multiple @ characters, which can cause a denial of service (DoS) attack")
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