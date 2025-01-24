import urllib3
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse, urljoin

# Suppress only the single InsecureRequestWarning from urllib3
urllib3.disable_warnings(InsecureRequestWarning)

# Create a PoolManager instance
http = urllib3.PoolManager()

# Define a function to make a request with manual redirect handling
def make_request_with_redirect_handling(url, method='POST', body=None, max_redirects=5):
    
    redirect_count = 0
    current_url = url

    while redirect_count <= max_redirects:
        response = http.request(method, current_url, body=body, redirect=False)

        if response.status in (301, 302, 303, 307, 308):
            redirect_url = response.get_redirect_location()
            if not redirect_url:
              break  # Exit if no redirect location is given
            
            parsed_redirect_url = urlparse(redirect_url)
            if not parsed_redirect_url.netloc:
              redirect_url = urljoin(current_url, redirect_url)

            
            
            if method == 'POST' and response.status not in (307, 308):
              print(f"Redirecting to {redirect_url} with GET, dropping body")
              method = 'GET'
              body = None
            else:
              print(f"Redirecting to {redirect_url}")
            
            current_url = redirect_url
            redirect_count += 1
            continue
        else:
            return response
    
    raise Exception(f"Too many redirects ({redirect_count}) encountered.")

# Example usage
url = 'http://example.com/some_endpoint'
body = {'key': 'value'}
response = make_request_with_redirect_handling(url, method='POST', body=body)
print(response.data)
