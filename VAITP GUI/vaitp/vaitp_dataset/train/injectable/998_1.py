import os
import stat

def secure_chmod(file_path, mode):
    # Ensure that the mode is within the valid range
    if mode < 0 or mode > 0o777:
        raise ValueError("Mode must be between 0 and 0o777")

    # Apply the permissions using os.chmod
    os.chmod(file_path, mode)

# Example usage
file_path = 'example_file.txt'
secure_chmod(file_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)  # Set permissions to 644