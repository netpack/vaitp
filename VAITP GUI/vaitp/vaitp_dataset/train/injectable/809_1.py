import os
import stat

def secure_jsnapy_directory(directory):
    # Set the directory permissions to prevent world writable access
    try:
        os.chmod(directory, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | 
                        stat.S_IRGRP | stat.S_IXGRP)  # Owner can read, write, execute; group can read, execute
    except OSError as e:
        print(f"Error setting permissions for directory {directory}: {e}")
        return

    # Secure all files within the directory
    for root, dirs, files in os.walk(directory):
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            try:
                os.chmod(dir_path, stat.S_IRUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP)  # Secure directories
            except OSError as e:
                print(f"Error setting permissions for directory {dir_path}: {e}")

        for file_name in files:
            file_path = os.path.join(root, file_name)
            try:
                os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)  # Owner can read and write; no group or other access
            except OSError as e:
                print(f"Error setting permissions for file {file_path}: {e}")

# Example usage
# secure_jsnapy_directory('/path/to/jsnapy/config')