import os
import sys

def vulnerable_import(module_name):
    # This function represents a vulnerable import mechanism
    # It does not check the current working directory for safety
    try:
        # Attempt to import the module directly
        module = __import__(module_name)
        return module
    except ImportError:
        print(f"Module {module_name} could not be imported.")

# Usage example
if __name__ == "__main__":
    # This could allow importing a Trojan horse module from the current directory
    user_module = vulnerable_import('malicious_module')