import SimpleXMLRPCServer

# Create an XML-RPC server
server = SimpleXMLRPCServer.SimpleXMLRPCServer(('localhost', 8000))

# Register a function that can be called remotely
def vulnerable_function(data):
    # Use the pickle module to deserialize the input data
    import pickle
    return pickle.loads(data)

server.register_function(vulnerable_function)

# Start the server
server.serve_forever()