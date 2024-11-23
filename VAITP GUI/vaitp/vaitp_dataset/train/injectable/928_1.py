import urllib3
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3
urllib3.disable_warnings(InsecureRequestWarning)

# Create a PoolManager instance
http = urllib3.PoolManager()

# Define a function to make a request with manual redirect handling
def make_request_with_redirect_handling(url, method='POST', body=None):
    response = http.request(method, url, body=body, redirect=False)
    
    # Check for redirect responses
    if response.status in (301, 302, 303):
        redirect_url = response.get_redirect_location()
        # Handle the redirect manually, stripping the body for GET requests
        if method == 'POST':
            print(f"Redirecting to {redirect_url} without body")
            response = http.request('GET', redirect_url)
        else:
            print(f"Redirecting to {redirect_url}")
            response = http.request(method, redirect_url)
    
    return response

# Example usage
url = 'http://example.com/some_endpoint'
body = {'key': 'value'}
response = make_request_with_redirect_handling(url, method='POST', body=body)
print(response.data)