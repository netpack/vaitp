from xmlrpc.server import SimpleXMLRPCServer
import html

def hello(name):
    return f"Hello, {name}!"

server = SimpleXMLRPCServer(("localhost", 8000))
server.register_function(hello)

# Sanitize the server_title field
server.server_title = html.escape("My XML-RPC Server")

print("Server running on port 8000...")
server.serve_forever()