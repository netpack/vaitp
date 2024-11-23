# Fixed version of the vulnerable code in d8s-htm package

import requests

def fetch_data(url):
    # Validate the URL to prevent code execution vulnerabilities
    if not url.startswith("https://trusted-domain.com/"):
        raise ValueError("Invalid URL: Only trusted domains are allowed.")
    
    response = requests.get(url)
    return response.json()

# Example usage
try:
    data = fetch_data("https://trusted-domain.com/api/data")
    print(data)
except ValueError as e:
    print(e)