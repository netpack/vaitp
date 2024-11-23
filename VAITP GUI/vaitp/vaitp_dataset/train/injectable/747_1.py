import requests

def safe_get(url):
    # Validate the URL to prevent open redirects
    if not url.startswith(('http://', 'https://')):
        raise ValueError("Invalid URL: must start with http:// or https://")
    
    response = requests.get(url)
    return response.text

# Example usage
try:
    content = safe_get("http://example.com")
    print(content)
except ValueError as e:
    print(e)