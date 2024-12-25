# Import the pydoc module
import pydoc
import socket

# Start a pydoc server on port 8000 with the --no-getfile option
# This will prevent the server from disclosing sensitive information

def ready():
    print("pydoc server ready on http://{}:8000".format(socket.gethostbyname(socket.gethostname())))

pydoc.serve(8000, callback=ready, no_getfile=True)