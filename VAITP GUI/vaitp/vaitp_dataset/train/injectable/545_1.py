import os
import stat

# Function to set correct permissions
def secure_installation(directory):
    # Ensure the directory exists
    if not os.path.exists(directory):
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as e:
            print(f"Error creating directory: {e}")
            return
    
    # Set permissions to the directory to be non-world-writable
    try:
        os.chmod(directory, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IROTH)
    except OSError as e:
            print(f"Error setting directory permissions: {e}")
            return

    # Walk through the directory and secure all files and subdirectories
    for root, dirs, files in os.walk(directory):
        for d in dirs:
            full_dir_path = os.path.join(root, d)
            try:
                os.chmod(full_dir_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IROTH)
            except OSError as e:
                print(f"Error setting subdirectory permissions: {e} for {full_dir_path}")
        for f in files:
            full_file_path = os.path.join(root, f)
            try:
                os.chmod(full_file_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
            except OSError as e:
                print(f"Error setting file permissions: {e} for {full_file_path}")

# Example usage
secure_installation('/path/to/installed/spe')
