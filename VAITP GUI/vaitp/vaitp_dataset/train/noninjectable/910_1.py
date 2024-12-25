import os
import os.path

def read_file(user_input):
    # Potentially unsafe file read operation
    base_directory = '/var/lib/susemanager/files'
    
    # Construct the absolute path and then remove the base path to
    # make sure that relative path traversal is not allowed.
    full_path = os.path.abspath(os.path.join(base_directory, user_input))
    
    # Verify that the requested path is under the base directory
    if not full_path.startswith(base_directory):
        raise Exception("Invalid path provided")
    
    # Read the file contents without proper validation
    with open(full_path, 'r') as file:
        return file.read()

# Example usage
user_input = '../etc/passwd'  # Malicious user input attempting path traversal
try:
    content = read_file(user_input)
    print(content)
except Exception as e:
    print(e)