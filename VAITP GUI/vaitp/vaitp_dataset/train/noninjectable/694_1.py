import os
import sys

def insecure_import(module_name):
    # This function imports a module without checking the current or parent directory
    __import__(module_name)

# Example usage
# This could potentially import a trojan horse .egg-info file if present
insecure_import('some_module')