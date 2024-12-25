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
        except ImportError:
            sys.path.pop(0)
            continue # Clean up sys.path and try the next path
        finally:
            sys.path.pop(0)  # Clean up sys.path
    return None

# Example usage
if __name__ == "__main__":
    module_name = "example_module"
    imported_module = secure_import(module_name)
    if imported_module:
      print(f"Successfully imported module: {imported_module}")
    else:
        print(f"Failed to import module: {module_name}")