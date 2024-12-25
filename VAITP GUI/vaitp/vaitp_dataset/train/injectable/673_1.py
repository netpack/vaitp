import os
import subprocess

def execute_command(command):
    # Ensure that only safe commands can be executed
    allowed_commands = ['ls', 'whoami', 'id']  # Example of allowed commands
    if command in allowed_commands:
        result = subprocess.run(command.split(), check=True, text=True, capture_output=True)
        return result.stdout
    else:
        raise PermissionError("Unauthorized command execution attempt.")

# Example usage
try:
    user_command = input("Enter a command to execute: ")
    output = execute_command(user_command)
    print(output)
except PermissionError as e:
    print(e)
except Exception as e:
    print("An error occurred:", e)