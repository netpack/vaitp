# Import the urllib3 module
import urllib3

# Define a benign URL
# This URL does not have many percent-encoded characters
url = "http://example.com/hello%20world"

# Create a connection pool
http = urllib3.PoolManager()

# Send a request with the benign URL
# This will not trigger the vulnerability in the urllib3 module
# The _encode_invalid_chars function will use a linear algorithm
# This will not result in a CPU denial of service
response = http.request("GET", url)