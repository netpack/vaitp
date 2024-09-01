from urllib.parse import urlparse
import requests

def fetch_url(url):
    # Parse the URL
    parsed_url = urlparse(url)
    
    # Extract the scheme and netloc
    scheme = parsed_url.scheme
    netloc = parsed_url.netloc
    
    # Construct the proxy URL
    proxy_url = f"{scheme}://{netloc}"
    
    # Set the proxy headers
    proxy_headers = {
        "Proxy-Authorization": "Basic QWxhZGprakdFRReGR5"
    }
    
    # Make the request using the proxy
    response = requests.get(url, proxies={"http": proxy_url, "https": proxy_url}, headers=proxy_headers)
    
    return response.text

# Example usage
url = "http://example.com\r\nProxy-Authorization: Basic injected-credentials"
print(fetch_url(url))