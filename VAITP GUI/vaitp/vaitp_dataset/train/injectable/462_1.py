from starlette.responses import Response
import re

def sanitize_header_value(value):
    # Sanitize the header value to prevent CRLF injection
    if re.search(r'[\r\n]', value):
        raise ValueError("Invalid header value")
    return value

def send_response(user_input):
    sanitized_input = sanitize_header_value(user_input)  # Sanitize input
    response = Response(content="Hello, World!")
    response.headers['X-Custom-Header'] = sanitized_input  # Use sanitized input
    return response