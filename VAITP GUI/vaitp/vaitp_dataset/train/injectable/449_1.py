import os
import sys

# Function to safely import a Python module
def safe_import(module_name):
    # Get the directory of the current script
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Check if the module is in the current directory
    if current_dir in sys.path:
        sys.path.remove(current_dir)  # Remove current directory from sys.path

    # Import the module safely
    module = __import__(module_name)
    
    # Restore the original sys.path
    sys.path.append(current_dir)
    
    return module

# Example usage: safely import a module named 'my_module'
my_module = safe_import('my_module')