import os
import stat

# Path to the directory containing the Python scripts
script_directory = '/path/to/spss/scripts'

# Set permissions to restrict access
def secure_script_permissions(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            # Change permissions to read and execute for owner only
            os.chmod(file_path, stat.S_IRUSR | stat.S_IXUSR)

# Call the function to secure script permissions
secure_script_permissions(script_directory)