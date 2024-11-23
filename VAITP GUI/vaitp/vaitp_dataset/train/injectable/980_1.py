import os
import sys

def secure_path_setup():
    # Get the current PATH
    current_path = os.environ.get('PATH', '')
    
    # Define secure directories
    secure_directories = [
        r'C:\Python27',
        r'C:\Python27\Scripts'
    ]
    
    # Check if any secure directories are in the PATH
    for directory in secure_directories:
        if directory in current_path:
            print(f"Warning: {directory} is in the PATH. This may pose a security risk.")
            # Optionally, remove or sanitize the PATH here
            # For example, you could log this or alert the administrator
            
    # Set the PATH to a safe value (this is an example, adjust as needed)
    safe_path = r'C:\SecurePythonPath'
    os.environ['PATH'] = safe_path

# Call the function to setup a secure path
secure_path_setup()