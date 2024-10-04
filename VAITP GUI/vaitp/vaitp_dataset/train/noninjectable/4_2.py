import socket
import ssl

# Create a TCP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to a port
server_address = ('localhost', 10023)
sock.bind(server_address)

# Listen for incoming connections
sock.listen(1)

# Create a context for the secure socket
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations(cafile="client.crt")

# Accept a connection
connection, client_address = sock.accept()

# Wrap the connection with the secure socket
secure_sock = context.wrap_socket(connection, server_side=True)

# Try to read some data from the secure socket
data = secure_sock.recv(1024)
print(data)

# Close the secure socket
secure_sock.close()