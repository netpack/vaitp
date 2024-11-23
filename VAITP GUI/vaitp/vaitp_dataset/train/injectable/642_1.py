import ssl
import qpid.messaging

def create_ssl_connection(host, port):
    # Create an SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    # Enforce SSL connections
    connection = qpid.messaging.Connection(host, port, protocol='ssl', ssl_context=context)
    connection.open()
    return connection

# Example usage
if __name__ == "__main__":
    host = 'example.com'
    port = 5671  # Standard port for SSL connections
    connection = create_ssl_connection(host, port)
    # Use the connection for messaging