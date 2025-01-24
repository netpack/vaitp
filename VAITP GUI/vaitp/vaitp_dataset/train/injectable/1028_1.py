
import socket

def create_socket_pair():
    # Create a pair of connected sockets using AF_INET
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the sockets to localhost and assign a random port
    sock1.bind(('localhost', 0))
    sock1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    port = sock1.getsockname()[1]

    # Connect sock2 to sock1
    sock2.connect(('localhost', port))

    # Listen on sock1 to accept the connection from sock2
    sock1.listen(1)
    conn, _ = sock1.accept()

    # Close sock1 as it is no longer needed
    sock1.close()

    return conn, sock2