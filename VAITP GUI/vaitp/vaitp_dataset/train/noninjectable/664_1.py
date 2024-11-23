import sys

def vulnerable_import(module_name):
    # Potentially unsafe: adds current working directory to sys.path
    sys.path.append('')  # This adds the current directory to the path

    # Importing the module without validation
    __import__(module_name)

# Example usage
vulnerable_import('malicious_module')  # Could lead to executing a Trojan horse