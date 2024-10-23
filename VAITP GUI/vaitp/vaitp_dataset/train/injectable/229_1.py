import requests

def fetch_data(url):
    # This request verifies SSL certificates
    response = requests.get(url, verify=True)
    return response.text

# Example usage
url = "https://example.com/api/data"
data = fetch_data(url)
print(data)