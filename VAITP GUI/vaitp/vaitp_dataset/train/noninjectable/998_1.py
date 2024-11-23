import os

def vulnerable_chmod(file_path):
    # This simulates the vulnerability by passing -1 as the mode
    os.chmod(file_path, -1)  # This could lead to world-writable permissions

# Example usage
file_path = 'example_file.txt'
vulnerable_chmod(file_path)  # This may create a file with unsafe permissions