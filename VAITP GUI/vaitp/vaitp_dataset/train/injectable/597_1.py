import ssl
import socket

def create_ssl_context():
    # Create an SSL context with proper hostname verification
    context = ssl.create_default_context()
    context.check_hostname = True  # Enable hostname checking
    context.verify_mode = ssl.CERT_REQUIRED  # Require a valid certificate
    return context

def connect_to_server(host, port):
    context = create_ssl_context()
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            print(ssock.version())

# Example usage
connect_to_server('example.com', 443)