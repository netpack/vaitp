import os

def secure_ftp_path(base_path, user_input_path):
    # Normalize the paths to prevent directory traversal
    normalized_path = os.path.normpath(user_input_path)
    
    # Ensure the normalized path starts with the base path
    if not normalized_path.startswith(base_path):
        raise ValueError("Invalid path access attempt detected.")
    
    # Construct the full path
    full_path = os.path.join(base_path, normalized_path)
    
    # Check if the path exists and is a file
    if os.path.isfile(full_path):
        with open(full_path, 'r') as file:
            return file.read()
    else:
        raise FileNotFoundError("Requested file not found.")

# Example usage
base_directory = '/secure/ftp/root'
user_input = '../etc/passwd'  # Simulated user input attempting directory traversal
try:
    content = secure_ftp_path(base_directory, user_input)
    print(content)
except Exception as e:
    print(e)