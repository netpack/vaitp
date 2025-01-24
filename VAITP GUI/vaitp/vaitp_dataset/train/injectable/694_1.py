import importlib
import os
import sys

def secure_import(module_name):
    
    trusted_dirs = [
        os.path.normpath(path)
        for path in sys.path
        if os.path.isdir(path)
    ]
    
    try:
      
        spec = importlib.util.find_spec(module_name)
        if spec is None:
            raise ImportError(f"Module '{module_name}' not found.")

        module_path = os.path.normpath(spec.origin)

        if not any(module_path.startswith(dir_) for dir_ in trusted_dirs) and not spec.submodule_search_locations:
            raise ImportError(f"Module '{module_name}' found at '{module_path}' is not in a trusted directory.")
        
        importlib.import_module(module_name)

    except ImportError as e:
        raise ImportError(f"Failed to import '{module_name}': {e}") from e

# Example usage
try:
    secure_import('some_module')
except ImportError as e:
    print(e)
