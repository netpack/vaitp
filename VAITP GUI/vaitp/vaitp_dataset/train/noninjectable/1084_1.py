import os

# Function to create a shared Python environment
def create_shared_environment(env_path):
    # Create a directory for the shared environment
    os.makedirs(env_path, exist_ok=True)
    # Allow all users to write to the environment directory
    os.chmod(env_path, 0o777)

# Example usage
create_shared_environment('/path/to/shared/python/environment')