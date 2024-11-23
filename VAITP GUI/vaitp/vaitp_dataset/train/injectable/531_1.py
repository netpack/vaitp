import os

def safe_read_file(file_path):
    # Ensure the file path is within a safe directory
    safe_directory = "/safe/directory/"
    if os.path.commonpath([file_path, safe_directory]) == safe_directory:
        with open(file_path, 'r') as file:
            return file.read()
    else:
        raise ValueError("Access to the specified file is not allowed.")

# Usage
try:
    code = safe_read_file("/safe/directory/example.py")
    print(code)
except ValueError as e:
    print(e)