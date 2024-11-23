import os
import stat

def secure_install_directory(directory):
    # Set the permissions to be more restrictive
    os.chmod(directory, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    
    # Optionally, remove group and other permissions
    for root, dirs, files in os.walk(directory):
        for dir in dirs:
            os.chmod(os.path.join(root, dir), stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        for file in files:
            os.chmod(os.path.join(root, file), stat.S_IRUSR | stat.S_IWUSR)

# Example usage
secure_install_directory('/path/to/install/directory')