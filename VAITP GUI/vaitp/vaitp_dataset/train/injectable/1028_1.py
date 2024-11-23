import socket

def create_socket_pair():
    # Create a pair of connected sockets using AF_INET
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the sockets to localhost and a free port
    sock1.bind(('localhost', 0))
    sock2.bind(('localhost', 0))

    # Get the port number assigned to sock1
    port = sock1.getsockname()[1]

    # Connect sock2 to sock1
    sock2.connect(('localhost', port))

    # Listen on sock1 to accept the connection from sock2
    sock1.listen(1)
    conn, _ = sock1.accept()

    return conn, sock2

# Example usage
conn, sock2 = create_socket_pair()
print("Connected sockets created successfully.")