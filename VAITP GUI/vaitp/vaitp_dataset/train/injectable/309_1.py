import awscrt
import awscrt.io
import socket

# Example PEM-encoded custom CA certificate and key (replace with actual values)
custom_ca_cert_pem = """
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJALa1fFQGZ1eHMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
...
-----END CERTIFICATE-----
"""

custom_ca_key_pem = """
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArhI8l...
-----END PRIVATE KEY-----
"""

# Create a custom CA
custom_ca = awscrt.io.CertificateAuthority(
    cert_pem=custom_ca_cert_pem,
    key_pem=custom_ca_key_pem
)

# Create a TLS context with the custom CA, ensuring proper validation
tls_context = awscrt.io.ClientTlsContext(
    alpn=['h2', 'http/1.1'],
    certificate_authorities=[custom_ca],  # Properly overriding the system CAs
    verify_peer=True  # Enforcing peer validation to ensure security
)

# Create a connection
#The TlsConnection does not exist. We need to create a socket, and then wrap that in a TlsConnection
host = "example.com"
port = 443

# Resolve host to IP address (this needs to be done)
try:
    addr_info = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    sock_addr = addr_info[0][4]
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(sock_addr)
    
    connection = awscrt.io.TlsConnection(tls_context=tls_context, socket=sock, server_name=host)

    # Attempt to connect to a server
    connection.connect() #Removed the connect function parameters

except socket.gaierror as e:
        print(f"Error resolving host {host}: {e}")
except Exception as e:
        print(f"An unexpected error occurred: {e}")
