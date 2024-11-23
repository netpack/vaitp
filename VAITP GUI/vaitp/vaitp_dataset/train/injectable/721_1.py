import importlib

# Whitelisted modules
WHITELISTED_MODULES = ['safe_module']

def safe_import(module_name):
    if module_name in WHITELISTED_MODULES:
        return importlib.import_module(module_name)
    else:
        raise ImportError(f"{module_name} is not a whitelisted module.")

# Example of a safe module
def safe_function():
    return "This is a safe function."

# Usage
try:
    # Attempt to import a whitelisted module
    module = safe_import('safe_module')
    print(module.safe_function())
except ImportError as e:
    print(e)