import os
import sys
import importlib

# Securely set the Python path to avoid untrusted directories
def secure_import(module_name):
    # Get the current working directory
    cwd = os.getcwd()
    
    # Check if the current working directory is trusted
    if cwd not in sys.path:
        sys.path.insert(0, cwd)

    # Import the module
    importlib.import_module(module_name)

# Usage example
if __name__ == "__main__":
    # Securely import a module
    try:
        secure_import('trusted_module')
        print("Module 'trusted_module' imported successfully.")
    except ModuleNotFoundError:
       print("Error: Module 'trusted_module' not found.")