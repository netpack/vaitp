import os

def read_file(user_input_path):
    # This could be a path to a file provided by a user
    file_path = os.path.expanduser(user_input_path)
    
    # Vulnerable: This follows symlinks without checking
    with open(file_path, 'r') as file:
        return file.read()

# Example usage
user_input = '~/sensitive_file.txt'  # User can specify a symlink
content = read_file(user_input)
print(content)