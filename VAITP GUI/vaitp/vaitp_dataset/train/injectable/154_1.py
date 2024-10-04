# Patched XML-RPC server using defusedxml to mitigate CVE-2014-3598
# This example assumes you are using Python 2.7 or later but not Python 3.x.
# For Python 3.x, use xmlrpc.server instead of SimpleXMLRPCServer and xmlrpc.client instead of xmlrpclib.

from SimpleXMLRPCServer import SimpleXMLRPCServer
import defusedxml.xmlrpc as xmlrpc

def sample_function(x):
    return f"Received: {x}"

server = SimpleXMLRPCServer(("localhost", 8000))
print("Listening on port 8000...")
server.register_function(sample_function, "sample_function")

server.serve_forever()