import os

# Vulnerable code that imports a module from the current working directory
def vulnerable_import(module_name):
    # This will import the module from the current working directory
    module = __import__(module_name)
    return module

# Example usage: importing a module named 'my_module' from the current directory
my_module = vulnerable_import('my_module')