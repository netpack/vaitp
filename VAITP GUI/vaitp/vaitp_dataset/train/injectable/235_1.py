import ssl
import socket

def make_https_connection(host, port):
    # Create a default SSL context that verifies certificates
    context = ssl.create_default_context()

    # The following lines ensure proper certificate validation
    context.check_hostname = True  # Verify the server's hostname
    context.verify_mode = ssl.CERT_REQUIRED  # Require a valid certificate

    # Establish a connection to the server
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            # Perform HTTPS operations here
            print(f"Successfully connected to {host} on port {port}")

make_https_connection("example.com", 443)