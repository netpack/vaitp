import pylibmc
from cryptography.fernet import Fernet
import os
import logging

class SecureMemcacheMiddleware:
    def __init__(self, app, encryption_key):
        self.app = app
        self.encryption_key = encryption_key
        self.memcache_client = pylibmc.Client(["127.0.0.1:11211"], binary=True, behaviors={"tcp_nodelay": True, "ketama": True})
        self.logger = logging.getLogger(__name__)


    def encrypt(self, data):
        fernet = Fernet(self.encryption_key)
        try:
            return fernet.encrypt(data.encode())
        except Exception as e:
            self.logger.error(f"Error during encryption: {e}")
            return None

    def decrypt(self, encrypted_data):
        fernet = Fernet(self.encryption_key)
        try:
            return fernet.decrypt(encrypted_data).decode()
        except Exception as e:
           self.logger.error(f"Error during decryption: {e}")
           return None

    def __call__(self, environ, start_response):
        try:
            encrypted_data = self.memcache_client.get('sensitive_key')
            if encrypted_data:
                sensitive_data = self.decrypt(encrypted_data)
                if sensitive_data is not None:
                    environ['sensitive_data'] = sensitive_data
                else:
                    environ['sensitive_data'] = "Decryption failed"
            else:
                environ['sensitive_data'] = "No data found"
        except Exception as e:
            self.logger.error(f"Error accessing memcache or processing data: {e}")
            environ['sensitive_data'] = "Error retrieving data"
        return self.app(environ, start_response)


def simple_app(environ, start_response):
    sensitive_data = environ.get('sensitive_data', 'No sensitive data')
    response_body = f"Sensitive Data: {sensitive_data}".encode('utf-8')
    status = '200 OK'
    headers = [('Content-Type', 'text/plain'), ('Content-Length', str(len(response_body)))]
    start_response(status, headers)
    return [response_body]


key = Fernet.generate_key()

app = SecureMemcacheMiddleware(simple_app, key)

if __name__ == "__main__":
    logging.basicConfig(level=logging.ERROR)
    from wsgiref.simple_server import make_server
    server = make_server('localhost', 8000, app)
    print("Serving on http://localhost:8000...")
    server.serve_forever()
