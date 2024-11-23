import os

def safe_read_file(base_directory, user_input):
    # Normalize the user input to prevent path traversal
    normalized_path = os.path.normpath(user_input)
    
    # Ensure the normalized path is within the base directory
    if not normalized_path.startswith(base_directory):
        raise ValueError("Access to the requested file is denied.")
    
    # Construct the full file path
    full_path = os.path.join(base_directory, normalized_path)
    
    # Read the file contents safely
    with open(full_path, 'r') as file:
        return file.read()

# Example usage
base_directory = '/var/lib/susemanager/files'
user_input = 'documents/report.txt'  # User input should be sanitized
try:
    content = safe_read_file(base_directory, user_input)
    print(content)
except ValueError as e:
    print(e)