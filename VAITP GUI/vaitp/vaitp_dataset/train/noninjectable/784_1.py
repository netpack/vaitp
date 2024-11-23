import os
from urllib.parse import unquote

def load_script(script_path):
    # Decode the URL-encoded path
    decoded_path = unquote(script_path)

    # Directly use the decoded path without proper validation
    # This allows for potential directory traversal attacks
    script_file_path = decoded_path

    # Load and execute the script
    with open(script_file_path, 'r') as script_file:
        exec(script_file.read())

# Example usage
load_script('/path/to/libreoffice/share/Scripts/python/../malicious_script.py')