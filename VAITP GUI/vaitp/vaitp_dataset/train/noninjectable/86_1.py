from xmlrpc.server import SimpleXMLRPCServer

def hello(name):
    return f"Hello, {name}!"

server = SimpleXMLRPCServer(("localhost", 8000))
server.register_function(hello)

# Vulnerable code: server_title is not sanitized
server.server_title = "My XML-RPC Server"

print("Server running on port 8000...")
server.serve_forever()

# The exploitation could be done with a client such as:
# import xmlrpc.client

# # Create a malicious server_title field
# malicious_title = "<script>alert('XSS')</script>"

# # Create an XML-RPC client
# client = xmlrpc.client.ServerProxy("http://localhost:8000")

# # Send a request to the server with the malicious server_title field
# try:
#     client.system.listMethods(malicious_title)
# except Exception as e:
#     print(e)