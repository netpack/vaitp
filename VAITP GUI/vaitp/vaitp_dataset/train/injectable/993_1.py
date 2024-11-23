import sys
import os

# Securely set the PYTHONPATH
def secure_import(module_name):
    # Get the current PYTHONPATH
    python_path = os.environ.get('PYTHONPATH', '').split(os.pathsep)

    # Filter out any paths that are not absolute or are in /tmp
    filtered_paths = [path for path in python_path if os.path.isabs(path) and path != '/tmp']

    # Attempt to import the module from the filtered paths
    for path in filtered_paths:
        sys.path.insert(0, path)  # Temporarily add the path to sys.path
        try:
            module = __import__(module_name)
            return module
        finally:
            sys.path.pop(0)  # Clean up sys.path

# Example usage
if __name__ == "__main__":
    module_name = "example_module"
    secure_import(module_name)