# Import the urllib3 library
import urllib3

# Create an HTTPS connection pool
# This will use the default SSLContext
http = urllib3.PoolManager()

# Define a malicious HTTPS proxy
# This proxy has a self-signed certificate
proxy = "https://malicious.com:8080"

# Define a target HTTPS URL
# This URL has a valid certificate
url = "https://example.com"

# Try to make a request through the proxy
# This will trigger the vulnerability in the urllib3 module
# The request function will not verify the hostname of the proxy certificate
# This means the proxy can intercept and modify the traffic
try:
    response = http.request("GET", url, retries=False, timeout=10, preload_content=False, proxy_url=proxy)
except urllib3.exceptions.MaxRetryError as e:
    print(f"Error during request: {e}")
    # Handle the error appropriately, perhaps by setting verify=True or specifying a valid ca_certs
