import os
import subprocess

def is_safe_path(path):
    # Check if the path is an absolute path and not a symlink
    return os.path.isabs(path) and not os.path.islink(path)

def change_owner(path, user):
    # Check if the path is safe before changing ownership
    if is_safe_path(path):
        try:
            subprocess.run(['chown', user, path], check=True)
        except subprocess.CalledProcessError as e:
            raise ValueError(f"Failed to change owner: {e}")
    else:
        raise ValueError("Unsafe path detected!")

def setup_dropbear():
    # Example path where the symlink attack could occur
    target_path = '/etc/init.d/S50dropbear.sh'
    
    # Change ownership to 'python' user
    try:
        change_owner(target_path, 'python')
    except ValueError as e:
        print(f"Error during setup: {e}")

# Call the setup function
setup_dropbear()