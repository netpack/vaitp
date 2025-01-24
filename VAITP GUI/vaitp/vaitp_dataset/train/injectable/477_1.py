
import os
import subprocess

def is_safe_path(path):
    if not path:
        return False
    normalized_path = os.path.normpath(path)
    if ".." in normalized_path or not os.path.isabs(normalized_path):
        return False
    return not os.path.islink(normalized_path)


def change_owner(path, user):
    if not is_safe_path(path):
         raise ValueError("Unsafe path detected!")
    os.chown(path, user)

def setup_dropbear():
    target_path = '/etc/init.d/S50dropbear.sh'
    try:
        change_owner(target_path, 'python')
    except ValueError as e:
        print(f"Error during setup: {e}")

setup_dropbear()