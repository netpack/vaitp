import os
import ctypes

def load_library_safely(library_name):
    # Get the current working directory
    cwd = os.getcwd()
    
    # Ensure the library is loaded from a safe location
    safe_path = os.path.join(os.path.dirname(__file__), library_name)

    if os.path.isfile(safe_path):
        # Load the library from a safe path
        return ctypes.CDLL(safe_path)
    else:
        raise FileNotFoundError(f"Library {library_name} not found in safe location.")

# Example usage
try:
    my_library = load_library_safely("my_safe_library.dll")
except Exception as e:
    print(f"Error: {e}")