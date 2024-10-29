import ssl
import socket

def create_ssl_connection(host, port):
    context = ssl.create_default_context()
    # Enable hostname verification
    connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
    try:
        connection.connect((host, port))
        # Additional verification can be done here if needed
        return connection
    except ssl.SSLError as e:
        print(f"SSL error: {e}")
        return None

# Usage
host = "example.com"
port = 443
conn = create_ssl_connection(host, port)
if conn:
    print("SSL connection established")
else:
    print("SSL connection failed")