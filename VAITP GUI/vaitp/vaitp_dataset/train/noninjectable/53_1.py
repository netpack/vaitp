import http.client # Python < 3.10

def vulnerable_function():
    conn = http.client.HTTPConnection("example.com")
    conn.request("GET", "/")

    # This is the vulnerable part: we don't check the response status code
    response = conn.getresponse()
    response.read()

vulnerable_function()