# Example of a fixed version of the code that avoids executing arbitrary code from untrusted sources

import requests

def safe_fetch_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Ensure we raise an error for bad responses
        return response.text
    except requests.RequestException as e:
        print(f"Error fetching URL: {e}")
        return None

# Usage
url = "https://example.com/safe-endpoint"
content = safe_fetch_url(url)
if content:
    print(content)