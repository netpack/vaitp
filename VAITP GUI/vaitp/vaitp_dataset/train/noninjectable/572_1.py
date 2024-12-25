import certifi
import ssl
import socket

# Create a context using the old certifi CA bundle that includes TrustCor certificates
context = ssl.create_default_context(cafile=certifi.where())

# Example of establishing a secure connection using the old context
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    with ssl.wrap_socket(sock, ssl_context=context, server_hostname='example.com') as s:
        s.connect(('example.com', 443))
        print(s.recv(1024))