# Fixed version of the d8s-urls package
# This code ensures that the package does not execute any untrusted code.

import requests

def safe_fetch_url(url):
    # Ensure the URL is from a trusted source
    trusted_sources = ["https://example.com", "https://another-trusted-source.com"]
    if any(url.startswith(source) for source in trusted_sources):
        response = requests.get(url)
        return response.text
    else:
        raise ValueError("Untrusted URL!")

# Example usage
try:
    content = safe_fetch_url("https://example.com/resource")
    print(content)
except ValueError as e:
    print(e)