import os
import sys

# Securely define the path to the Python modules
MODULES_DIR = '/usr/local/lib/my_secure_modules'

def load_module(module_name):
    # Ensure the module is loaded from a trusted directory
    module_path = os.path.join(MODULES_DIR, module_name)
    if os.path.isfile(module_path):
        exec(open(module_path).read(), globals())
    else:
        raise ImportError(f"Module {module_name} not found in secure directory.")

# Example usage
if __name__ == "__main__":
    try:
        load_module('deployUtil.py')
        load_module('vds_bootstrap.py')
    except ImportError as e:
        print(e)
        sys.exit(