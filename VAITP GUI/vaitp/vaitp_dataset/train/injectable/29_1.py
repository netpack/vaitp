from urllib.parse import urlparse, urlunparse
import requests

def fetch_url(url):
    # Parse the URL
    parsed_url = urlparse(url)
    
    # Reconstruct the URL, sanitizing the path
    sanitized_path = parsed_url.path.replace("\r", "").replace("\n", "")
    sanitized_url = urlunparse((parsed_url.scheme, parsed_url.netloc, sanitized_path, parsed_url.params, parsed_url.query, parsed_url.fragment))
    
    # Extract the scheme and netloc
    scheme = parsed_url.scheme
    netloc = parsed_url.netloc
    
    # Construct the proxy URL
    proxy_url = f"{scheme}://{netloc}"
    
    # Set the proxy headers
    proxy_headers = {
        "Proxy-Authorization": "Basic QWxhZGprakdFRReGR5"
    }
    
    # Make the request using the proxy, but don't send the Proxy-Authorization header to the target
    response = requests.get(sanitized_url, proxies={"http": proxy_url, "https": proxy_url})
    
    return response.text

# Example usage
url = "http://example.com\r\nProxy-Authorization: Basic injected-credentials"
print(fetch_url(url))