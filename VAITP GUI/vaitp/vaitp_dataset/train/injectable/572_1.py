import certifi
import ssl

# Create a context that uses the updated certifi CA bundle
context = ssl.create_default_context(cafile=certifi.where())

# Example of establishing a secure connection using the updated context
with ssl.wrap_socket(socket.socket(), ssl_context=context) as s:
    s.connect(('example.com', 443))
    print(s.recv(1024))