# Import the http.server module
import http.server

# Create a HTTP request handler class
class MyHandler(http.server.BaseHTTPRequestHandler):

# Define a method to handle GET requests
def do_GET(self):

# Send a 301 redirect response
self.send_response(301)

# Set the Location header to the URL path
# This will not protect against multiple (/) at the beginning of the path
# For example, if the path is //example.com, this will redirect to example.com
self.send_header("Location", self.path)

# End the headers
self.end_headers()

# Create a HTTP server object
server = http.server.HTTPServer(("", 8000), MyHandler)

# Start the server
server.serve_forever()