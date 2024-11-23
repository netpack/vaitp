import os

def read_file(user_input):
    # Potentially unsafe file read operation
    base_directory = '/var/lib/susemanager/files'
    
    # Directly using user input to construct the file path
    full_path = os.path.join(base_directory, user_input)
    
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