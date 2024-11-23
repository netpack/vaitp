import qpid.messaging

def create_connection(host, port, qpid_protocol):
    # Create a connection without enforcing SSL
    connection = qpid.messaging.Connection(host, port, protocol=qpid_protocol)
    connection.open()
    return connection

# Example usage
if __name__ == "__main__":
    host = 'example.com'
    port = 5671  # Standard port for SSL connections
    qpid_protocol = 'ssl'  # Protocol set to ssl, but not enforced
    connection = create_connection(host, port, qpid_protocol)
    # Use the connection for messaging