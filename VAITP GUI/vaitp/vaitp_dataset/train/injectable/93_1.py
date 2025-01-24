import urllib3
import certifi

# Create a PoolManager with a custom SSL context and specify the CA certificates
ssl_context = urllib3.ssl_.create_urllib3_ssl_context()
ssl_context.load_verify_locations(certifi.where())
pool_manager = urllib3.PoolManager(ssl_context=ssl_context)

# Make a request to a server with a self-signed certificate
try:
    response = pool_manager.request('GET', 'https://self-signed-server.com', preload_content=False)
    print(response.status)
    response.release_conn()
except urllib3.exceptions.MaxRetryError as e:
    print(f"Error during request: {e}")
except Exception as e:
     print(f"An unexpected error occurred: {e}")