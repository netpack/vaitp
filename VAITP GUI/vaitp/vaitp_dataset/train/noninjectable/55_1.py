# Import the pydoc module, which provides a simple HTTP server for browsing documentation
import pydoc

# Define a function to start the pydoc server
def start_pydoc_server():
    # Start the pydoc server on localhost at port 7464
    # This is the vulnerable part of the code, as it allows an attacker to access sensitive information
    pydoc.server('localhost', 7464)

# Check if this script is being run directly (not being imported as a module)
if __name__ == '__main__':
    # Call the function to start the pydoc server
    start_pydoc_server()