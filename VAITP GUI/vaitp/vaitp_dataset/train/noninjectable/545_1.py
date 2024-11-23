import os

# Function to install the application with world-writable permissions
def insecure_installation(directory):
    # Set permissions to the directory to be world-writable
    os.makedirs(directory, exist_ok=True)
    os.chmod(directory, 0o777)  # World-writable permissions

# Example usage
insecure_installation('/path/to/installed/spe')