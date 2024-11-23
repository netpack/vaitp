import os
import subprocess
import sys

def secure_launch_python_interpreter():
    # Get the current working directory
    current_dir = os.getcwd()
    
    # Define a safe path for executing commands
    safe_path = os.path.abspath("/path/to/safe/directory")

    # Change the working directory to a safe path
    os.chdir(safe_path)

    # Launch the Python interpreter securely
    try:
        subprocess.run([sys.executable, '-i'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error launching Python interpreter: {e}")

# Call the secure function to launch the interpreter
secure_launch_python_interpreter()