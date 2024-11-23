import os

def insecure_install_directory(directory):
    # Set the permissions to be more permissive
    os.makedirs(directory, exist_ok=True)
    os.chmod(directory, 0o777)  # Read, write, and execute for everyone

    # Create a sample file in the directory
    with open(os.path.join(directory, 'sample_file.txt'), 'w') as f:
        f.write('This is a sample file.')

# Example usage
insecure_install_directory('/path/to/install/directory')