import subprocess
import os
import sys

def secure_python_execution():
    # Use the absolute path of the system Python interpreter
    system_python = '/usr/bin/python3'  # Adjust this path as necessary
    # Check if the system Python exists
    if not os.path.isfile(system_python):
        print("System Python interpreter not found.")
        sys.exit(1)

    # Execute a command using the secure Python interpreter
    try:
        subprocess.run([system_python, 'your_script.py'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing script: {e}")

# Call the function to execute the script securely
secure_python_execution()