import ssl
import socket

def create_ssl_connection(host, port):
    context = ssl.create_default_context()
    # No hostname verification is performed here
    connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
    connection.connect((host, port))
    return connection

# Usage
host = "example.com"
port = 443
conn = create_ssl_connection(host, port)
print("SSL connection established")