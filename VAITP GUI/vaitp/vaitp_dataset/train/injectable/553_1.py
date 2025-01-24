import os
import stat

def secure_install_directory(directory):
    # Set the permissions to be more restrictive
    try:
        os.chmod(directory, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    except OSError as e:
        print(f"Error changing permissions for directory {directory}: {e}")
        return
    
    # Optionally, remove group and other permissions
    for root, dirs, files in os.walk(directory):
        for dir in dirs:
            full_dir_path = os.path.join(root, dir)
            try:
                os.chmod(full_dir_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            except OSError as e:
                print(f"Error changing permissions for directory {full_dir_path}: {e}")
        for file in files:
            full_file_path = os.path.join(root, file)
            try:
                os.chmod(full_file_path, stat.S_IRUSR | stat.S_IWUSR )
            except OSError as e:
                print(f"Error changing permissions for file {full_file_path}: {e}")