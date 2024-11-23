import os
import stat

# Function to set secure permissions for a directory
def secure_directory_permissions(directory_path):
    # Set permissions to allow only the owner to read, write, and execute
    os.chmod(directory_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

# Example usage
directory_to_secure = '/path/to/directory'
secure_directory_permissions(directory_to_secure)