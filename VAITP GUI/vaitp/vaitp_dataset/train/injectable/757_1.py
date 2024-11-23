import os

ALLOWED_MODES = {'r', 'w', 'a'}
ALLOWED_DIRS = {'/allowed_directory/'}

def safe_open(file_path, mode):
    # Validate mode
    if mode not in ALLOWED_MODES:
        raise ValueError("Invalid file mode.")
    
    # Validate directory
    normalized_path = os.path.normpath(file_path)
    if not any(normalized_path.startswith(os.path.normpath(allowed_dir)) for allowed_dir in ALLOWED_DIRS):
        raise ValueError("Access to this directory is not allowed.")
    
    return open(file_path, mode)

# Example usage
try:
    with safe_open('/allowed_directory/my_file.txt', 'w') as f:
        f.write('Hello, World!')
except ValueError as e:
    print(e)