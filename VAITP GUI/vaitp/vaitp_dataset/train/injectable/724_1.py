import ssl
import socket

def create_ssl_context():
    context = ssl.create_default_context()
    # Enable hostname checking
    context.check_hostname = True
    # Set the minimum protocol version
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context

def connect_to_server(hostname, port):
    context = create_ssl_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            print(f"SSL established. Peer: {ssock.getpeercert()}")

# Example usage
connect_to_server('example.com', 443)