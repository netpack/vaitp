import os
import sys

# Function to safely import a Python module
def safe_import(module_name):
    # Get the directory of the current script
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Check if the module is in the current directory
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)  # Add current directory to sys.path if not present

    try:
        # Import the module safely
        module = __import__(module_name)
    except ImportError:
        print(f"Error: Could not import module '{module_name}'")
        return None
    finally:
        # Restore the original sys.path (remove current dir if added)
        if current_dir in sys.path:
             sys.path.remove(current_dir)

    
    return module

# Example usage: safely import a module named 'my_module'
# This will raise an ImportError if my_module doesn't exist.
# This could be modified to instead provide a custom error handling
my_module = safe_import('my_module')