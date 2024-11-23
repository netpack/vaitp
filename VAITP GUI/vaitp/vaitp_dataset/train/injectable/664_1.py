import os
import sys

def secure_import(module_name):
    # Store the original sys.path
    original_sys_path = sys.path.copy()

    # Clear sys.path to prevent untrusted directories
    sys.path = []

    try:
        # Import the module safely
        __import__(module_name)
    finally:
        # Restore the original sys.path
        sys.path = original_sys_path

# Example usage
secure_import('trusted_module')