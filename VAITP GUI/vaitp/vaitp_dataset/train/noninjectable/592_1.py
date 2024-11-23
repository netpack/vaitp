import ssl
import socket

# Create a secure socket without proper certificate verification
def create_insecure_socket(host, port):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_NONE  # This allows for certificate verification to be bypassed
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as insecure_sock:
            return insecure_sock

# Example usage
insecure_socket = create_insecure_socket('example.com', 443)