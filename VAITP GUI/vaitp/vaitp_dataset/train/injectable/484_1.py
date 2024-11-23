import importlib
import os

def secure_import(module_name):
    allowed_modules = ['safe_module1', 'safe_module2']  # Define allowed modules
    if module_name in allowed_modules:
        return importlib.import_module(module_name)
    else:
        raise ImportError(f"Module '{module_name}' is not allowed.")

# Example usage
try:
    module = secure_import('unsafe_module')  # This will raise an ImportError
except ImportError as e:
    print(e)