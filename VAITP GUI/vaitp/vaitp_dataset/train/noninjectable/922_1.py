from waitress import serve

# Example of a vulnerable Waitress server setup (before the patch)
def vulnerable_int_parsing(value):
    # Vulnerable parsing method that does not adhere to RFC7230
    return int(value)  # This can lead to parsing issues with +10 or 0x01

def handle_request(environ, start_response):
    # Example of handling a request without strict validation
    headers = environ.get('HTTP_HEADERS', '')
    # Here, we are not validating headers as per RFC7230
    response_body = b'Hello, World!'
    status = '200 OK'
    start_response(status, [('Content-Type', 'text/plain'), ('Content-Length', str(len(response_body)))])
    return [response_body]

if __name__ == "__main__":
    serve(handle_request, host='0.0.0.0', port=8080)