import os

# Function that creates a directory with insecure default permissions
def create_insecure_directory(directory_path):
    # Create a directory with default permissions
    os.mkdir(directory_path)

# Example usage
directory_to_create = '/path/to/insecure_directory'
create_insecure_directory(directory_to_create)