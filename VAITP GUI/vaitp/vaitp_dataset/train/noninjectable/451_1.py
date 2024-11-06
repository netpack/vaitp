import os
import subprocess

def execute_command(command):
    # Execute the command in the current working directory
    os.system(command)

# Assume the user is in a directory that contains a malicious script named "malicious_script.bat"
# User executes a command
execute_command("some_command")