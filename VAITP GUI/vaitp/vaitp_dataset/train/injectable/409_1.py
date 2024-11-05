import httpx
from urllib.parse import urlparse

def is_safe_url(url):
    parsed_url = urlparse(url)
    # Only allow HTTP/HTTPS and block localhost or internal IPs
    return parsed_url.scheme in {"http", "https"} and parsed_url.hostname not in {"localhost", "127.0.0.1"}

def fetch_data(url):
    if not is_safe_url(url):
        raise ValueError("Unsafe URL provided!")
    
    client = httpx.Client()
    response = client.get(url)
    return response.text

# Example usage
user_input = "http://localhost:8000/admin"  # Malicious input
try:
    data = fetch_data(user_input)
except ValueError as e:
    print(e)  # Output: Unsafe URL provided!