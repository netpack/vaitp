import os
import subprocess

def execute_python_version():
    current_directory = os.getcwd()
    version_file_path = os.path.join(current_directory, '.python-version')

    if os.path.exists(version_file_path):
        with open(version_file_path, 'r') as f:
            version = f.read().strip()
            pyenv_root = os.path.expanduser("~/.pyenv")
            version_path = os.path.join(pyenv_root, "versions", version, "bin", "python")


            if os.path.isfile(version_path):
                try:
                    subprocess.run([version_path, "--version"], check=True)
                except subprocess.CalledProcessError:
                    print(f"Error executing python version {version}")

            else:
                print(f"Python version {version} not found.")

# Example usage
execute_python_version()