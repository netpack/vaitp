import requests
from urllib.parse import urlparse

class Resource:
    @staticmethod
    def get(url):
        # Validate the URL to prevent SSRF
        parsed_url = urlparse(url)
        
        # Only allow certain protocols and domains
        if parsed_url.scheme not in ['http', 'https']:
            raise ValueError("Invalid URL scheme. Only HTTP and HTTPS are allowed.")
        
        # Example: Restrict to a specific domain
        allowed_domains = ['api.recurly.com']
        if parsed_url.netloc not in allowed_domains:
            raise ValueError("URL not allowed.")
        
        response = requests.get(url)
        return response.json()

# Example usage
url = "http://api.recurly.com/resource"  # Allowed URL
data = Resource.get(url)
print(data)