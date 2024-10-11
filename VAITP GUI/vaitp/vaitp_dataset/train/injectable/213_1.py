import httplib

# Create an HTTP connection
conn = httplib.HTTPConnection('localhost', 8000)

# Check the length of the Host header before sending the request
host_header = 'localhost'
if len(host_header) < 256:
    conn.request('GET', '/', headers={'Host': host_header})
else:
    print("Error: Host header is too long")

# Get the response
response = conn.getresponse()