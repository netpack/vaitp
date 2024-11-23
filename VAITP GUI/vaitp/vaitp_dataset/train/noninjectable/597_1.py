import ssl
import socket

def connect_to_server(host, port):
    # Create an SSL context without hostname verification
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_NONE  # Disable certificate verification

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock) as ssock:
            print(ssock.version())

# Example usage
connect_to_server('example.com', 443)