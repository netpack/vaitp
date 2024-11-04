# Hypothetical example
import ssl
import socket

def create_ssl_connection(hostname, port):
    context = ssl.create_default_context()
    # Secure code: properly verifying hostname
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    try:
        conn.connect((hostname, port))
    except ssl.SSLError as e:
        print(f"SSL error: {e}")
        raise
    return conn