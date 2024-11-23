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

    # Here, the connection is not verified before returning the sockets
    sock2.connect(('localhost', port))

    return sock1, sock2

# Example usage
sock1, sock2 = create_socket_pair()
print("Socket pair created (vulnerable to connection race).")