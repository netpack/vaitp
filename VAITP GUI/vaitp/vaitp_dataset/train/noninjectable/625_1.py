import os

def vulnerable_ftp_path(base_path, user_input_path):
    # Directly join user input with base path
    full_path = os.path.join(base_path, user_input_path)
    
    # Read the file without any validation
    with open(full_path, 'r') as file:
        return file.read()

# Example usage
base_directory = '/secure/ftp/root'
user_input = '../etc/passwd'  # Simulated user input attempting directory traversal
try:
    content = vulnerable_ftp_path(base_directory, user_input)
    print(content)
except Exception as e:
    print(e)