import os
import sys

def load_module(module_name):
    # This function directly imports a module without checking the path
    return __import__(module_name)

# Example usage
# If there is a malicious module named 'my_trojan_module.py' in the current directory,
# it could be imported without any checks.
my_module = load_module('my_trojan_module')