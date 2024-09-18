import urllib.request

def non_vulnerable_function(url):
    # Create a URL request
    req = urllib.request.Request(url)

    # Send the request and get the response
    response = urllib.request.urlopen(req)

    # Read the response content
    content = response.read().decode('utf-8')

    # Use a safe string method to parse the content
    if "a" in content or "b" in content:
        print("Pattern found")
    else:
        print("Pattern not found")

# Example usage
url = "http://example.com/valid-content"
non_vulnerable_function(url)