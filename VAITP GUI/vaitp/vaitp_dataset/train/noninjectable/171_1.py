# This is a simplified and vulnerable XML-RPC server example
from SimpleXMLRPCServer import SimpleXMLRPCServer
import xmlrpclib

def vulnerable_function(arg):
    # Pretend this function processes some XML-RPC request
    print(f"Received: {arg}")
    return f"Processed: {arg}"

server = SimpleXMLRPCServer(("localhost", 8000))
print("Listening on port 8000...")
server.register_function(vulnerable_function, "vulnerable_function")

server.serve_forever()