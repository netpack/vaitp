import os

def execute_python_version():
    current_directory = os.getcwd()
    version_file_path = os.path.join(current_directory, '.python-version')

    if os.path.exists(version_file_path):
        with open(version_file_path, 'r') as f:
            version = f.read().strip()
            # Directly constructing the path without validation
            pyenv_root = os.path.expanduser("~/.pyenv")
            version_path = os.path.join(pyenv_root, "versions", version)

            # This could lead to execution of arbitrary shims
            if os.path.isfile(version_path):
                os.system(version_path)
            else:
                print(f"Python version {version} not found.")

# Example usage
execute_python_version()