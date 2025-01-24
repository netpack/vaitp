import os
import sys
import subprocess

def activate_virtualenv():
    current_dir = os.getcwd()
    venv_file = os.path.join(current_dir, '.venv')

    if os.path.isfile(venv_file):
        print("Warning: .venv file detected, skipping activation to prevent potential security risks.")
        return

    # Proceed to activate the virtual environment if no .venv file is found
    venv_path = os.path.join(current_dir, 'venv')
    if os.path.isdir(venv_path):
        activate_script = os.path.join(venv_path, 'bin', 'activate')
        if os.path.isfile(activate_script):
            try:
                subprocess.run([activate_script], shell=False, check=True, executable='/bin/bash')
            except subprocess.CalledProcessError as e:
                  print(f"Error activating virtual environment: {e}")
        else:
            print("No activation script found.")
    else:
        print("No virtual environment found.")

if __name__ == "__main__":
    activate_virtualenv()