# Hypothetical example
# After patch
import os

def read_file(file_path):
    # Ensure the file path is within a specific directory
    base_dir = "/safe/directory"
    safe_path = os.path.join(base_dir, file_path)

    # Normalize the path to prevent traversal
    if not safe_path.startswith(base_dir):
        raise ValueError("Invalid file path!")

    with open(safe_path, 'r') as file:
        return file.read()

# Example usage
content = read_file("example.txt")  # Safe usage