import awscrt
import awscrt.io
import socket
import ssl

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
host = "example.com"
port = 443

try:
    # Resolve host to IP address
    addr_info = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    sock_addr = addr_info[0][4]
    
    # Create a socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Wrap the socket with SSL/TLS using the provided context
    ssl_sock = ssl.wrap_socket(sock, 
                                 ssl_version=ssl.PROTOCOL_TLSv1_2,
                                 server_hostname=host,
                                 do_handshake_on_connect=False,
                                 ca_certs=None,
                                 cert_reqs=ssl.CERT_REQUIRED)
    
    # Connect to the server
    ssl_sock.connect(sock_addr)

    # Manually perform the handshake for proper certificate validation.
    ssl_sock.do_handshake()

    # Create the awscrt TlsConnection using the wrapped ssl socket
    connection = awscrt.io.TlsConnection(tls_context=tls_context, socket=ssl_sock.fileno(), server_name=host)
    
    #Perform the handshake again, now through the awscrt interface.
    connection.connect()


except socket.gaierror as e:
    print(f"Error resolving host {host}: {e}")
except ssl.SSLError as e:
    print(f"SSL Error: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")