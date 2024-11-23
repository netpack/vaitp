import os

# Vulnerable code that can import modules from the current working directory
def unsafe_import(module_name):
    # This will import the module from the current working directory or any subdirectory
    module = __import__(module_name)
    return module

# Usage example
if __name__ == "__main__":
    # Example of importing a potentially malicious module
    my_module = unsafe_import('my_module')