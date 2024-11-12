# secure_app.py

import pylibmc
from cryptography.fernet import Fernet

class SecureMemcacheMiddleware:
    def __init__(self, app, encryption_key):
        self.app = app
        self.encryption_key = encryption_key
        self.memcache_client = pylibmc.Client(["127.0.0.1:11211"], binary=True)

    def encrypt(self, data):
        fernet = Fernet(self.encryption_key)
        return fernet.encrypt(data.encode())

    def decrypt(self, encrypted_data):
        fernet = Fernet(self.encryption_key)
        return fernet.decrypt(encrypted_data).decode()

    def __call__(self, environ, start_response):
        # Retrieve encrypted data from memcache
        encrypted_data = self.memcache_client.get('sensitive_key')
        if encrypted_data:
            # Decrypt the data before using it
            sensitive_data = self.decrypt(encrypted_data)
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

# Generate a key for encryption
key = Fernet.generate_key()

# Wrap the WSGI application with the secure middleware
app = SecureMemcacheMiddleware(simple_app, key)

if __name__ == "__main__":
    from wsgiref.simple_server import make_server
    server = make_server('localhost', 8000, app)
    print("Serving on http://localhost:8000...")
    server.serve_forever()