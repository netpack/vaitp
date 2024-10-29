import awscrt
import awscrt.io

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

# Create a TLS context with the custom CA
tls_context = awscrt.io.ClientTlsContext(
    alpn=['h2', 'http/1.1'],
    certificate_authorities=[custom_ca]  # Appending user-supplied CA
)

# Create a connection
connection = awscrt.io.TlsConnection(tls_context=tls_context)

# Attempt to connect to a server
connection.connect(server_name="example.com")