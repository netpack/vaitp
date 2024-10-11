import tarfile
import os

# Create a tarfile object
tar = tarfile.TarFile('example.tar', 'w')

# Define a function to check for directory traversal
def is_safe_path(path):
    return os.path.realpath(path).startswith(os.getcwd())

# Add a file to the tarfile with a path that could trigger the vulnerability
file_path = '../etc/passwd'
if is_safe_path(file_path):
    tar.add(file_path)
else:
    print("Error: File path is not safe")