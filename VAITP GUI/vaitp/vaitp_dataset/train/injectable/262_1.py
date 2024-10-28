# pal_chain/base.py (Patched Version)

import restricted_modules  # List of allowed modules

def dynamic_import(module_name):
    # Check if the module is in the allowed list
    if module_name not in restricted_modules.ALLOWED_MODULES:
        raise ImportError(f"Importing {module_name} is not allowed.")
    
    module = __import__(module_name)
    return module