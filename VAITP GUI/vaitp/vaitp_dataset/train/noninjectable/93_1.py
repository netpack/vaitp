import urllib3

# Create a PoolManager with a custom SSL context
ssl_context = urllib3.ssl_.create_urllib3_ssl_context()
pool_manager = urllib3.PoolManager.ssl_context = ssl_context

# Make a request to a server with a self-signed certificate
response = pool_manager.request('GET', 'https://self-signed-server.com')

print(response.status)