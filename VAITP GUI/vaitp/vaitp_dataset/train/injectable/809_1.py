import os
import stat

def secure_jsnapy_directory(directory):
    # Set the directory permissions to prevent world writable access
    os.chmod(directory, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | 
                      stat.S_IRGRP | stat.S_IXGRP)  # Owner can read, write, execute; group can read, execute

    # Secure all files within the directory
    for root, dirs, files in os.walk(directory):
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            os.chmod(dir_path, stat.S_IRUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP)  # Secure directories

        for file_name in files:
            file_path = os.path.join(root, file_name)
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)  # Owner can read and write; no group or other access

# Example usage
secure_jsnapy_directory('/path/to/jsnapy/config')