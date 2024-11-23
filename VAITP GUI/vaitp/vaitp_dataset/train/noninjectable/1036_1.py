from multipart import MultipartParser

# Simulating a vulnerable scenario
def handle_request(environ):
    content_type = environ.get('CONTENT_TYPE', '')
    body = environ['wsgi.input'].read()
    
    # Vulnerable parsing of multipart data
    parser = MultipartParser(body, content_type)  # This could lead to excessive CPU usage
    # Process the parsed data...