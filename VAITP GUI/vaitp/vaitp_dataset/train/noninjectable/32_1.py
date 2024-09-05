import urllib3 # urllib3 < 1.26.5

def fetch_url(url):
    http = urllib3.PoolManager()
    response = http.request('GET', url)
    return response.data

# Example usage:
url = "http://example.com@" * 1000  # URL with many @ characters
try:
    data = fetch_url(url)
    print(data)
except Exception as e:
    print(f"Error: {e}")