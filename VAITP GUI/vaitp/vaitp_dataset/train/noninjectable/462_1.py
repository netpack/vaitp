from starlette.responses import Response

def send_response(user_input):
    # Vulnerable code that directly uses user input in headers
    response = Response(content="Hello, World!")
    response.headers['X-Custom-Header'] = user_input  # Directly using user input
    return response