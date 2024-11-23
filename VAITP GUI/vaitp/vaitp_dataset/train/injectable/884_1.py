import os
import shutil

# Path to the original docker-compose.yml file
original_docker_compose_path = '/path/to/original/docker-compose.yml'
# Path to the protected docker-compose.yml file
protected_docker_compose_path = '/path/to/protected/docker-compose.yml'

# Function to copy the original docker-compose.yml to a protected location
def protect_docker_compose():
    if os.path.exists(original_docker_compose_path):
        shutil.copy(original_docker_compose_path, protected_docker_compose_path)
        # Set permissions to read-only
        os.chmod(protected_docker_compose_path, 0o444)  # Read-only for all users

# Call the function to protect the docker-compose.yml file
protect_docker_compose()