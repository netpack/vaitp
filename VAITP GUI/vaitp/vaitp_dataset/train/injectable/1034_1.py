import os
import subprocess
import sys
import venv

# Properly quote the path to prevent command injection
def create_virtualenv(env_dir):
    if os.path.exists(env_dir):
        raise FileExistsError(f"Directory {env_dir} already exists.")
    
    builder = venv.EnvBuilder(with_pip=True)
    builder.create(env_dir)

# Example usage
if __name__ == "__main__":
    # Create a virtual environment safely
    env_directory = "myenv"  # Example of a safe directory name
    create_virtualenv(env_directory)
    
    # Activate the virtual environment safely
    activate_script = os.path.join(env_directory, 'bin', 'activate')
    subprocess.run([sys.executable, '-m', 'venv', activate_script])