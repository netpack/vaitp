import certifi
import ssl
import socket

# Create a context that uses the updated certifi CA bundle
context = ssl.create_default_context(cafile=certifi.where())

# Example of establishing a secure connection using the updated context
with socket.socket() as sock:
    with context.wrap_socket(sock, server_hostname='example.com') as s:
        s.connect(('example.com', 443))
        print(s.recv(1024))