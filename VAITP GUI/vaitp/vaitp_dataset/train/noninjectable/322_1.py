import requests

def fetch_data(url):
    # Vulnerable code that does not validate the URL
    response = requests.get(url)
    return response.json()

# Example usage
data = fetch_data("http://malicious-domain.com/api/data")  # Potentially harmful URL
print(data)