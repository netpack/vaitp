import urllib.request
import re

def vulnerable_function(url):
    # Create a URL request
    req = urllib.request.Request(url)

    # Send the request and get the response
    response = urllib.request.urlopen(req)

    # Read the response content
    content = response.read().decode('utf-8')

    # Use a vulnerable regular expression to parse the content
    pattern = r"(a|b)*"
    re.search(pattern, content)

# Example usage
url = "http://example.com/malicious-content"
vulnerable_function(url)