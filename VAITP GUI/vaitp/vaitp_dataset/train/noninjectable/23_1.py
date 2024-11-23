import os
import sys

# Simulating the insecure addition of user-writable directories to the PATH
def add_user_writable_path():
    # This represents a user-writable directory
    user_writable_directory = r"C:\Users\Public\WritableDirectory"

    # Get current PATH
    current_path = os.environ.get('PATH', '')
    
    # Adding a user-writable directory to the PATH
    new_path = current_path + os.pathsep + user_writable_directory
    os.environ['PATH'] = new_path

if __name__ == "__main__":
    add_user_writable_path()
    print("Insecure PATH modified:", os.environ['PATH'])