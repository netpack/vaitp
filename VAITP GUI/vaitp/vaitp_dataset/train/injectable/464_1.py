import os

def save_file(user_input_path, data):
    # Check if the path is a symlink
    if os.path.islink(user_input_path):
        raise ValueError("Symlinks are not allowed.")

    # Ensure the path is a valid file path and within allowed directories
    if not os.path.abspath(user_input_path).startswith('/allowed/directory/'):
        raise ValueError("Invalid file path.")

    # Save data to the specified path
    with open(user_input_path, 'w') as file:
        file.write(data)

# Example usage
user_input = '/path/to/user/specified/file.txt'  # This should not be a symlink
data_to_save = 'Sensitive data'
try:
    save_file(user_input, data_to_save)
except ValueError as e:
    print(f"Error: {e}")