import os
from urllib.parse import unquote

def safe_file_access(file_path):
    # Normalize the path to prevent directory traversal
    base_dir = "/path/to/allowed/directory"
    normalized_path = os.path.normpath(unquote(file_path))
    
    # Ensure the file path is within the allowed directory
    if not normalized_path.startswith(base_dir):
        raise ValueError("Access to the requested file is not allowed.")
    
    # Open and read the file if the path is safe
    with open(normalized_path, 'r') as file:
        return file.read()

# Example usage
try:
    content = safe_file_access("/path/to/allowed/directory/safe_file.txt")
    print(content)
except ValueError as e:
    print(e)