import ssl
import qpid.messaging

def create_ssl_connection(host, port):
    # Create an SSL context
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)  # Changed to SERVER_AUTH
    
    # Enforce SSL connections
    connection = qpid.messaging.Connection(host, port, ssl_context=context, transport='ssl') # Added transport='ssl' and removed protocol
    connection.open()
    return connection

# Example usage
if __name__ == "__main__":
    host = 'example.com'
    port = 5671  # Standard port for SSL connections
    try:
      connection = create_ssl_connection(host, port)
      # Use the connection for messaging
      print("SSL Connection established successfully")
    except qpid.messaging.ConnectionError as e:
      print(f"Error establishing SSL Connection: {e}")