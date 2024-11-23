import ssl
import socket

def create_ssl_context():
    context = ssl.create_default_context()
    # Hostname checking is not enabled, which represents the vulnerability
    context.check_hostname = False
    return context

def connect_to_server(hostname, port):
    context = create_ssl_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock) as ssock:
            print(f"SSL established. Peer: {ssock.getpeercert()}")

# Example usage
connect_to_server('example.com', 443)