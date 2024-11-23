import ssl
import socket

# Create a secure socket with proper certificate verification
def create_secure_socket(host, port):
    context = ssl.create_default_context()  # Create a context that verifies certificates
    # Alternatively, you can specify ssl.CERT_REQUIRED for strict verification
    # context.verify_mode = ssl.CERT_REQUIRED
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as secure_sock:
            return secure_sock

# Example usage
secure_socket = create_secure_socket('example.com', 443)