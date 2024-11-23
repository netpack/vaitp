import os

def secure_file_write(file_path, content):
    # Check if the file path is safe and does not overwrite critical files
    if not os.path.abspath(file_path).startswith(os.path.abspath('/safe/directory/')):
        raise ValueError("Unsafe file path!")
    
    with open(file_path, 'w') as file:
        file.write(content)

# Example usage
try:
    secure_file_write('/safe/directory/example.py', 'print("Hello, World!")')
except ValueError as e:
    print(e)