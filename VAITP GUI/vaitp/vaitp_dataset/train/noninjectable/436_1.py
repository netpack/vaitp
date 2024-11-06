import requests

def fetch_data(url):
    response = requests.get(url)  # No certificate validation
    return response.content