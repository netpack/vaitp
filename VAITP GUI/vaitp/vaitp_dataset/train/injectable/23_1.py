import os
import sys

def secure_path():
    # Ensuring that only secure directories are added to the PATH
    secure_directories = [r"C:\Python\Scripts", r"C:\Python"]
    
    # Get current PATH
    current_path = os.environ.get('PATH', '')
    
    # Filter out user-writable directories
    filtered_path = []
    for directory in current_path.split(os.pathsep):
        if os.access(directory, os.W_OK):
            print(f"Warning: User-writable directory found - {directory}")
        else:
            filtered_path.append(directory)

    # Add only secure directories
    filtered_path.extend(secure_directories)
    os.environ['PATH'] = os.pathsep.join(filtered_path)

if __name__ == "__main__":
    secure_path()
    print("Secure PATH set.")