# Import the ssl module
import ssl

# Create a SSL context object
context = ssl.create_default_context()

# Open a malicious URL with a CRLF injection
response = context.wrap_socket().connect(('example.com', 443))
response.sendall(b'GET /%0D%0AHost:%20evil.com HTTP/1.1\r\n\r\n')

# Print the response data
print(response.recv(1024))