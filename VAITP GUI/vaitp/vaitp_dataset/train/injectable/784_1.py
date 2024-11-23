import os
from urllib.parse import unquote

def load_script(script_path):
    # Sanitize the input to prevent directory traversal
    base_directory = '/path/to/libreoffice/share/Scripts/python'
    user_directory = '/path/to/libreoffice/user/Scripts/python'

    # Decode the URL-encoded path
    decoded_path = unquote(script_path)

    # Ensure the decoded path is within the allowed directories
    if not (decoded_path.startswith(base_directory) or decoded_path.startswith(user_directory)):
        raise ValueError("Access denied: Invalid script path")

    # Normalize the path to prevent directory traversal
    normalized_path = os.path.normpath(decoded_path)

    # Check if the normalized path still starts with the allowed base directory
    if not (normalized_path.startswith(base_directory) or normalized_path.startswith(user_directory)):
        raise ValueError("Access denied: Invalid script path after normalization")

    # Load and execute the script
    with open(normalized_path, 'r') as script_file:
        exec(script_file.read())

# Example usage
try:
    load_script('/path/to/libreoffice/share/Scripts/python/my_script.py')
except ValueError as e:
    print(e)