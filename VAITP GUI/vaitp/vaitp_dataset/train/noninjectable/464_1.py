import os

def save_file(user_input_path, data):
    # This function saves data to a user-specified path
    # Vulnerable to symlink attacks
    with open(user_input_path, 'w') as file:
        file.write(data)

# Example usage
user_input = '/path/to/user/specified/file.txt'  # This could be a symlink
data_to_save = 'Sensitive data'
save_file(user_input, data_to_save)