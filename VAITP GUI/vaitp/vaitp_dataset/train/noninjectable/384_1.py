# Hypothetical example
import ssl
import socket

def create_ssl_connection(hostname, port):
    context = ssl.create_default_context()
    # Vulnerable code: not verifying hostname
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    conn.connect((hostname, port))
    return conn