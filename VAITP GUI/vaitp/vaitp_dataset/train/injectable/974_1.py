import os
import stat
import platform

def secure_permissions(python_directory):
    if platform.system() == 'Windows':
        return
    # Set permissions to allow only the owner to write
    for root, dirs, files in os.walk(python_directory):
        # Set directory permissions
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            try:
                os.chmod(dir_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            except OSError:
                pass

        # Set file permissions
        for file_name in files:
            file_path = os.path.join(root, file_name)
            try:
                os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
if platform.system() != 'Windows':
    secure_permissions(r'/opt/python311')