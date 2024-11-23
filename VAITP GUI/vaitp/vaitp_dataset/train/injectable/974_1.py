import os
import stat

def secure_permissions(python_directory):
    # Set permissions to allow only the owner to write
    for root, dirs, files in os.walk(python_directory):
        # Set directory permissions
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            os.chmod(dir_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)

        # Set file permissions
        for file_name in files:
            file_path = os.path.join(root, file_name)
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

# Secure the permissions of the C:\Python311 directory
secure_permissions(r'C:\Python311')