import qpid.messaging

def create_connection(host, port, qpid_protocol):
    # Create a connection without enforcing SSL
    try:
        connection = qpid.messaging.Connection(host=host, port=port, protocol=qpid_protocol)
        connection.open()
        return connection
    except qpid.messaging.exceptions.ConnectionError as e:
        print(f"Error creating connection: {e}")
        return None


# Example usage
if __name__ == "__main__":
    host = 'example.com'
    port = 5671  # Standard port for SSL connections
    qpid_protocol = 'ssl'  # Protocol set to ssl, but not enforced
    connection = create_connection(host, port, qpid_protocol)
    if connection:
        # Use the connection for messaging
        print("Connection successful")
        connection.close()
    else:
      print("Connection failed")