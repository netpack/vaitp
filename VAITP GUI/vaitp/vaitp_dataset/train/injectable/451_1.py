import os
import subprocess

def execute_command(command):
    # Use a safe environment by specifying the command explicitly
    safe_command = ["some_command"]  # Avoid passing user input directly
    # Use subprocess.run with cwd set to a safe directory
    subprocess.run(safe_command, cwd=os.path.expanduser("~"), check=True)

# User executes a command
execute_command("some_command")