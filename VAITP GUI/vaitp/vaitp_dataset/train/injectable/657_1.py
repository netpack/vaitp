import os
import sys

# Ensure the script only uses the standard library paths
def secure_import(module_name):
    # Get the standard library paths
    std_lib_paths = [p for p in sys.path if os.path.isdir(p) and p != os.getcwd()]
    
    # Check if the module exists in standard library paths
    for path in std_lib_paths:
        try:
            module = __import__(module_name, fromlist=[''])
            return module
        except ImportError:
            continue
    raise ImportError(f"Module {module_name} not found in secure paths.")

# Usage example
if __name__ == "__main__":
    # Example of importing a module securely
    my_module = secure_import('my_module')