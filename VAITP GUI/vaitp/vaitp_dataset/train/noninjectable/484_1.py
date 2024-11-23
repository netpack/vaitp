import importlib

def insecure_import(module_name):
    # Arbitrarily import any module without restriction
    return importlib.import_module(module_name)

# Example usage
module = insecure_import('os')  # This could allow arbitrary code execution