import os
import sys
import importlib.util

# Securely define the path to the Python modules
MODULES_DIR = '/usr/local/lib/my_secure_modules'

def load_module(module_name):
    # Ensure the module is loaded from a trusted directory
    module_path = os.path.join(MODULES_DIR, module_name)
    if os.path.isfile(module_path):
        spec = importlib.util.spec_from_file_location(module_name.replace('.py', ''), module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        sys.modules[module_name.replace('.py', '')] = module
        
    else:
        raise ImportError(f"Module {module_name} not found in secure directory.")

# Example usage
if __name__ == "__main__":
    try:
        load_module('deployUtil.py')
        load_module('vds_bootstrap.py')
    except ImportError as e:
        print(e)