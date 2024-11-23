import os

def safe_include(file_path):
    # Define a safe directory to include files from
    safe_directory = "/path/to/safe/directory"
    
    # Normalize the file path to prevent directory traversal
    normalized_path = os.path.normpath(file_path)
    
    # Check if the normalized path starts with the safe directory
    if not normalized_path.startswith(os.path.abspath(safe_directory)):
        raise ValueError("Unauthorized file access attempt detected.")
    
    # Safely read the contents of the file
    with open(normalized_path, 'r') as file:
        return file.read()

# Example usage
try:
    content = safe_include("somefile.txt")  # Only allow files within the safe directory
    print(content)
except ValueError as e:
    print(e)