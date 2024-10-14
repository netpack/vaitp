import httplib

# Create an HTTP connection
conn = httplib.HTTPConnection('localhost', 8000)

# Send a request with a crafted HTTP header
conn.request('GET', '/', headers={'Host': 'a' * 1024})

# Get the response
response = conn.getresponse()