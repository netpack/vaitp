import os
import sys
import logging

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
             logging.warning(f"Warning: {directory} is in the PATH. This may pose a security risk.")

    # Construct a safe PATH, including only absolute paths and essential directories
    safe_directories = [
        r'C:\Windows\system32',
        r'C:\Windows',
        r'C:\Windows\System32\Wbem',
        r'C:\Windows\System32\WindowsPowerShell\v1.0'
    ]

    safe_path = os.pathsep.join(safe_directories)

    # Update the PATH environment variable
    os.environ['PATH'] = safe_path
    
    #Verify path is safe
    current_path_after_update = os.environ.get('PATH', '')
    for directory in secure_directories:
        if directory in current_path_after_update:
            logging.error(f"Error: {directory} is still in the PATH after update")

if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
    secure_path_setup()
