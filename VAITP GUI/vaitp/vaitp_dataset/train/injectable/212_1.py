import SimpleXMLRPCServer
import json

# Create an XML-RPC server
server = SimpleXMLRPCServer.SimpleXMLRPCServer(('localhost', 8000))

# Register a function that can be called remotely
def safe_function(data):
    # Use the json module to deserialize the input data
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        print("Error: Invalid input data")

server.register_function(safe_function)

# Start the server
server.serve_forever()