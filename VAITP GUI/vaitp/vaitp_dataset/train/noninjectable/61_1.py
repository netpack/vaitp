import urllib3

def vulnerable_function(url, headers):
    http = urllib3.PoolManager()
    request = http.request('GET', url, headers=headers)
    return request.data

# Example usage:
url = "https://example.com"
headers = {
    "Transfer-Encoding": "chunked",
    "Content-Length": "0"
}
chunked_payload = "5\r\nHello\r\n0\r\n\r\n"
vulnerable_function(url, headers)

# Send the chunked payload as a separate request
http = urllib3.PoolManager()
request = http.request('POST', url, body=chunked_payload)