import ssl
import socket

def make_https_connection(host, port):
    context = ssl.create_default_context()
    # The following line is the vulnerable part # It does not verify the server's certificate
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            # Perform HTTPS operations here
            pass

make_https_connection("example.com", 443)