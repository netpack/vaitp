import os
import sys

def secure_import(module_name):
    # Get the current working directory
    current_dir = os.getcwd()
    
    # Get the parent directory
    parent_dir = os.path.dirname(current_dir)
    
    # Define a list of trusted directories (e.g., system paths)
    trusted_dirs = ["/usr/local/lib/python3.x/dist-packages", "/usr/lib/python3.x/dist-packages"]

    # Check if the current or parent directory is in the trusted directories
    if current_dir in trusted_dirs or parent_dir in trusted_dirs:
        # Proceed to import the module
        __import__(module_name)
    else:
        raise ImportError("Untrusted directory: Cannot import from current or parent directory.")

# Example usage
try:
    secure_import('some_module')
except ImportError as e:
    print(e)