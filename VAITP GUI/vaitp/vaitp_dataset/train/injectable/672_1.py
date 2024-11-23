import ssl
import urllib.request

# Define the server URL
server_url = 'https://example.com/api'

# Create an SSL context that verifies the server's certificate
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = True
ssl_context.verify_mode = ssl.CERT_REQUIRED

# Load trusted CA certificates
ssl_context.load_default_certs()

# Make a secure request to the server
with urllib.request.urlopen(server_url, context=ssl_context) as response:
    data = response.read()
    print(data)