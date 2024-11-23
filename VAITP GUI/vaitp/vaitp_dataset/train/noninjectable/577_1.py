import os
import sys

# Uncontrolled search path for imports
def unsafe_import(module_name):
    # Appending current directory to sys.path
    sys.path.append(os.getcwd())

    # Attempt to import the module
    try:
        module = __import__(module_name)
        return module
    except ImportError as e:
        print(f"Error importing module {module_name}: {e}")
        return None

# Example usage
if __name__ == "__main__":
    # Import a module without any restrictions
    my_module = unsafe_import('my_module')