import os
import sys

# Vulnerable code demonstrating the untrusted search path
def vulnerable_import(module_name):
    # Current working directory is included in sys.path
    current_dir = os.getcwd()
    sys.path.append(current_dir)  # Current directory is added to sys.path

    # Import the module, which could be a Trojan horse
    __import__(module_name)

# Example usage
if __name__ == "__main__":
    vulnerable_import('some_module')  # Replace 'some_module' with the actual module name