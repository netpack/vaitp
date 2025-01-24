import os
import sys
import importlib

def safe_import(module_name):
    # Ensure PYTHONPATH does not include untrusted directories
    trusted_paths = ["/usr/lib/python3/dist-packages", "/usr/local/lib/python3/dist-packages"]
    
    # Get current PYTHONPATH and split into directories
    current_paths = os.environ.get('PYTHONPATH', '').split(os.pathsep)
    
    # Filter out untrusted paths
    safe_paths = [path for path in current_paths if path in trusted_paths]

    # Set the safe PYTHONPATH
    os.environ['PYTHONPATH'] = os.pathsep.join(safe_paths)
    
    # Import the module safely
    try:
        importlib.import_module(module_name)
    except ImportError:
        print(f"Could not import module: {module_name}")


# Example usage
safe_import('some_module')