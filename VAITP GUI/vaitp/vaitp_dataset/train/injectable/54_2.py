# Import the urllib.request and urllib.error modules
import urllib.request
import urllib.error

# Define an HTTP server URL
url = "http://http.server"

# Define a timeout in seconds
timeout = 10

# Try to open the URL using the urllib.request module
# Pass the timeout argument to the urlopen function
try:
    response = urllib.request.urlopen(url, timeout=timeout)
    # Do something with the response
except urllib.error.URLError as e:
    # Handle the exception
    print(e)