import os
import subprocess

# Vulnerable code that does not properly quote paths
def create_virtualenv(env_dir):
    if os.path.exists(env_dir):
        raise FileExistsError(f"Directory {env_dir} already exists.")
    
    # This command is vulnerable to injection if env_dir is not properly sanitized
    subprocess.run(f"python3 -m venv {env_dir}", shell=True)

# Example usage
if __name__ == "__main__":
    # Example of a potentially unsafe directory name
    env_directory = "myenv; rm -rf /"  # This is a malicious input
    create_virtualenv(env_directory)
    
    # Activating the virtual environment (vulnerable to command injection)
    activate_script = os.path.join(env_directory, 'bin', 'activate')
    subprocess.run(f"source {activate_script}", shell=True)