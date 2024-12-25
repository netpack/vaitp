import os

def save_file(user_input_path, data):
    # Check if the path is a symlink
    if os.path.islink(user_input_path):
        raise ValueError("Symlinks are not allowed.")

    # Ensure the path is a valid file path and within allowed directories
    allowed_dir = '/allowed/directory/'
    abs_path = os.path.abspath(user_input_path)
    if not abs_path.startswith(allowed_dir):
        raise ValueError("Invalid file path.")

    # Save data to the specified path
    try:
        os.makedirs(os.path.dirname(user_input_path), exist_ok=True)
        with open(user_input_path, 'w') as file:
            file.write(data)
    except OSError as e:
         raise ValueError(f"Error saving file: {e}")


# Example usage
user_input = '/allowed/directory/path/to/user/specified/file.txt'  # This should not be a symlink
data_to_save = 'Sensitive data'
try:
    save_file(user_input, data_to_save)
except ValueError as e:
    print(f"Error: {e}")
