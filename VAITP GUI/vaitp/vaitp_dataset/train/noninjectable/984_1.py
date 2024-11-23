import urllib.request

def fetch_data(url):
    # Fetch data without verifying SSL certificates (vulnerable to MITM)
    response = urllib.request.urlopen(url)
    return response.read()

# Example usage
url = "https://example.com/data"
data = fetch_data(url)
print(data)