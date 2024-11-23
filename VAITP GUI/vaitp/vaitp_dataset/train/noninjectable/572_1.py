import certifi
import ssl

# Create a context using the old certifi CA bundle that includes TrustCor certificates
context = ssl.create_default_context(cafile=certifi.where())

# Example of establishing a secure connection using the old context
with ssl.wrap_socket(socket.socket(), ssl_context=context) as s:
    s.connect(('example.com', 443))
    print(s.recv(1024))