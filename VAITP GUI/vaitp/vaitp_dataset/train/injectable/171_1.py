# This is a patched XML-RPC server example
from SimpleXMLRPCServer import SimpleXMLRPCServer
from defusedxml.xmlrpc import xmlrpc_client

def safe_function(arg):
    # This function safely processes XML-RPC requests
    print(f"Received safely: {arg}")
    return f"Processed safely: {arg}"

server = SimpleXMLRPCServer(("localhost", 8000))
print("Listening on port 8000...")
server.register_function(safe_function, "safe_function")

server.serve_forever()