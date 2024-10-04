# Vulnerable XML-RPC server using xmlrpclib (Python 2)
# DO NOT USE IN PRODUCTION

from SimpleXMLRPCServer import SimpleXMLRPCServer
import xmlrpclib

def sample_function(x):
    return f"Received: {x}"

server = SimpleXMLRPCServer(("localhost", 8000))
print("Listening on port 8000...")
server.register_function(sample_function, "sample_function")

server.serve_forever()