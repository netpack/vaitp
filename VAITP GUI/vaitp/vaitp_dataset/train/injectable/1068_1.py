import re
import requests

def is_valid_url(url):
    # Basic validation to ensure the URL is safe
    regex = re.compile(
        r'^(?:http|https)://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    return re.match(regex, url) is not None

def save_url_to_cache(path):
    if is_valid_url(path):
        response = requests.get(path)
        # Process the response
    else:
        raise ValueError("Invalid URL provided.")

# Example usage
try:
    save_url_to_cache("http://example.com")
except ValueError as e:
    print(e