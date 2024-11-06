import requests

def fetch_data(url):
    response = requests.get(url, verify=True)  # Enforcing certificate validation
    return response.content