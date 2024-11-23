import sys
import os

# Vulnerable import function
def vulnerable_import(module_name):
    # Search for modules in /tmp before using PYTHONPATH
    tmp_path = '/tmp'
    if os.path.isdir(tmp_path):
        sys.path.insert(0, tmp_path)  # Add /tmp to the beginning of sys.path

    # Now attempt to import the module
    module = __import__(module_name)
    return module

# Example usage
if __name__ == "__main__":
    module_name = "malicious_module"
    vulnerable_import(module_name)