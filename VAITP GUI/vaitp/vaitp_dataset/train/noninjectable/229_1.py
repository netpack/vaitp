import requests

def fetch_data(url):
    # This request does not verify SSL certificates
    response = requests.get(url, verify=False)
    return response.text

# Example usage
url = "https://example.com/api/data"
data = fetch_data(url)
print(data)