import os
import sys

def safe_import(module_name):
    # Get the absolute path of the current script
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define a safe path for the module
    safe_path = os.path.join(current_dir, 'safe_modules')

    # Check if the safe path exists in sys.path
    if safe_path not in sys.path:
        sys.path.insert(0, safe_path)

    try:
        # Attempt to import the module safely
        module = __import__(module_name)
        return module
    except ImportError:
        print(f"Module {module_name} could not be imported.")

# Usage example
if __name__ == "__main__":
    safe_module = safe_import('my_safe_module')