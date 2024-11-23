import os
import subprocess

# Function to safely execute commands
def safe_execute(command):
    # Ensure that the command is not harmful
    allowed_commands = ['ls', 'whoami']  # Example of allowed commands
    if command in allowed_commands:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout
    else:
        return "Command not allowed."

# Example of using the safe_execute function
if __name__ == "__main__":
    user_command = input("Enter a command to execute: ")
    output = safe_execute(user_command)
    print(output)