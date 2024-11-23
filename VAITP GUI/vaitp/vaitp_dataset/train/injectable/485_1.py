# Example of a fixed allowmodule function to prevent unauthorized imports

ALLOWED_MODULES = {
    'math',
    'datetime',
    # Add other safe modules here
}

def allowmodule(module_name):
    if module_name in ALLOWED_MODULES:
        return __import__(module_name)
    else:
        raise ImportError(f"Importing module '{module_name}' is not allowed.")

# Usage
try:
    safe_math = allowmodule('math')  # Allowed
    unsafe_module = allowmodule('os')  # Not allowed, raises ImportError
except ImportError as e:
    print(e)