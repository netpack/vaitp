import os
import stat

# Function to secure the Python environment directory
def secure_environment_directory(env_path):
    # Set permissions to allow only the owner to write
    os.chmod(env_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IROTH)

# Example usage
secure_environment_directory('/path/to/python/environment')