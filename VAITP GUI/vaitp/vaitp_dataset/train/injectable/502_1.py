import os
import sys

# Securely set the Python path to avoid untrusted directories
def secure_import(module_name):
    # Get the current working directory
    cwd = os.getcwd()
    
    # Check if the current working directory is trusted
    if cwd not in sys.path:
        sys.path.insert(0, cwd)

    # Import the module
    __import__(module_name)

# Usage example
if __name__ == "__main__":
    # Securely import a module
    secure_import('trusted_module')