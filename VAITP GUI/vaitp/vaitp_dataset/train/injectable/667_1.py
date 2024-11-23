import os
import subprocess

# Function to execute a command securely
def secure_execute(command):
    # Ensure the command is from a predefined list of safe commands
    safe_commands = ['ls', 'whoami', 'pwd']  # Example safe commands
    if command in safe_commands:
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        return result.stdout
    else:
        raise ValueError("Unauthorized command execution attempt.")

# Example usage
try:
    output = secure_execute('ls')  # This is a safe command
    print(output)
except ValueError as e:
    print(e)