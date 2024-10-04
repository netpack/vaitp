# Import the pydoc module
import pydoc

# Start a pydoc server on port 8000 with the --no-getfile option
# This will prevent the server from disclosing sensitive information
pydoc.serve(8000, ready, no_getfile=True)