import sys
import os

def safe_import(module_name):
    # Ensure that the module is imported from a trusted location
    if os.path.dirname(module_name) not in sys.path:
        raise ImportError(f"Untrusted import attempt from {module_name}")
    return __import__(module_name)

# Example usage
try:
    my_module = safe_import('my_trusted_module')
except ImportError as e:
    print(e)