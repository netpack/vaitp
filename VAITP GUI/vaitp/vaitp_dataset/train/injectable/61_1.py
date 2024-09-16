import urllib3

def secure_function(url, headers, body):
    # Sanitize the headers to prevent header injection
    sanitized_headers = {}
    for key, value in headers.items():
        if key in ["Content-Type", "Accept", "Accept-Language", "Accept-Encoding"]:
            sanitized_headers[key] = value
        else:
            raise ValueError(f"Invalid header: {key}")

    http = urllib3.PoolManager()
    request = http.request('POST', url, headers=sanitized_headers, body=body)
    return request.data

# Example usage:
url = "https://example.com"
headers = {
    "Transfer-Encoding": "chunked",
    "Content-Length": "0"
}
chunked_payload = "5\r\nHello\r\n0\r\n\r\n"
secure_function(url, headers, chunked_payload)