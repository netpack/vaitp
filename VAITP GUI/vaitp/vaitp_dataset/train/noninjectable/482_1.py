# vulnerable_app.py

import pylibmc

class VulnerableMemcacheMiddleware:
    def __init__(self, app):
        self.app = app
        self.memcache_client = pylibmc.Client(["127.0.0.1:11211"], binary=True)

    def __call__(self, environ, start_response):
        # Retrieve sensitive data from memcache without encryption
        sensitive_data = self.memcache_client.get('sensitive_key')
        if sensitive_data:
            environ['sensitive_data'] = sensitive_data
        else:
            environ['sensitive_data'] = "No data found"
        return self.app(environ, start_response)

# Example WSGI application
def simple_app(environ, start_response):
    sensitive_data = environ.get('sensitive_data', 'No sensitive data')
    response_body = f"Sensitive Data: {sensitive_data}".encode('utf-8')
    status = '200 OK'
    headers = [('Content-Type', 'text/plain'), ('Content-Length', str(len(response_body)))]
    start_response(status, headers)
    return [response_body]

# Wrap the WSGI application with the vulnerable middleware
app = VulnerableMemcacheMiddleware(simple_app)

if __name__ == "__main__":
    from wsgiref.simple_server import make_server
    server = make_server('localhost', 8000, app)
    print("Serving on http://localhost:8000...")
    server.serve_forever()