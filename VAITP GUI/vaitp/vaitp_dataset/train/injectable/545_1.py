import os
import stat

# Function to set correct permissions
def secure_installation(directory):
    # Set permissions to the directory to be non-world-writable
    os.chmod(directory, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

# Example usage
secure_installation('/path/to/installed/spe')