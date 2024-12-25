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
    try:
        response = requests.get(url, proxies={"http": proxy_url, "https": proxy_url}, headers=proxy_headers)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        return response.text
    except requests.exceptions.RequestException as e:
         print(f"Error fetching URL: {e}")
         return None

# Example usage
url = "http://example.com" 
print(fetch_url(url))