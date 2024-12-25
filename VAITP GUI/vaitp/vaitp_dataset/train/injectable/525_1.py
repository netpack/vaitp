import os
import subprocess
import sys

def secure_launch_python_interpreter():
    # Get the current working directory
    current_dir = os.getcwd()
    
    # Define a safe path for executing commands
    safe_path = os.path.abspath("/tmp") # Changed to /tmp for testing, should be changed to a proper safe location

    # Change the working directory to a safe path
    try:
        os.chdir(safe_path)
    except FileNotFoundError:
        print(f"Error: Safe path '{safe_path}' not found. Exiting.")
        return
    except PermissionError:
        print(f"Error: No permission to access '{safe_path}'. Exiting.")
        return
    
    # Launch the Python interpreter securely
    try:
        subprocess.run([sys.executable, '-i'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error launching Python interpreter: {e}")
    finally:
        os.chdir(current_dir)

# Call the secure function to launch the interpreter
secure_launch_python_interpreter()