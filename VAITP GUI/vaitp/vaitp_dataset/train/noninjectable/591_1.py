import os

# Path to the directory containing the Python scripts
script_directory = '/path/to/spss/scripts'

# Set weak permissions that allow everyone to write
def set_weak_permissions(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            # Change permissions to allow everyone to write
            os.chmod(file_path, 0o666)  # rw-rw-rw-

# Call the function to set weak permissions
set_weak_permissions(script_directory)