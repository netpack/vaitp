import os
import shutil
import stat

# Path to the original docker-compose.yml file
original_docker_compose_path = '/path/to/original/docker-compose.yml'
# Path to the protected docker-compose.yml file
protected_docker_compose_path = '/path/to/protected/docker-compose.yml'

# Function to copy the original docker-compose.yml to a protected location
def protect_docker_compose():
    if not os.path.exists(original_docker_compose_path):
        return
    
    try:
        shutil.copy2(original_docker_compose_path, protected_docker_compose_path)
        # Set permissions to read-only for the owner, group, and others.
        os.chmod(protected_docker_compose_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    except (IOError, OSError) as e:
        print(f"Error protecting file: {e}")
        return

# Call the function to protect the docker-compose.yml file
protect_docker_compose()