import os
import sys

def safe_import(module_name):
    # Get the absolute path of the current working directory
    current_dir = os.path.abspath(os.getcwd())
    
    # Get the directory of the module to be imported
    module_path = os.path.dirname(module_name)
    
    # Ensure the module path is safe (not in the current working directory)
    if module_path and os.path.abspath(module_path) == current_dir:
        raise ImportError("Unsafe import from the current working directory is not allowed.")
    
    # Proceed with the import if it's safe
    return __import__(module_name)

# Example usage
try:
    my_module = safe_import('my_trojan_module')
except ImportError as e:
    print(e)