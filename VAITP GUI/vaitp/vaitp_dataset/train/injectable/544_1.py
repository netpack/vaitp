import os
import subprocess

def safe_execute(command):
    # Validate the command to ensure it is safe
    allowed_commands = {'ls', 'dir', 'echo'}
    command_parts = command.split()

    if command_parts[0] in allowed_commands:
        # Execute the command safely
        result = subprocess.run(command_parts, capture_output=True, text=True)
        return result.stdout
    else:
        raise ValueError("Invalid command")

# Example usage
try:
    user_input = input("Enter a command to execute: ")
    output = safe_execute(user_input)
    print(output)
except Exception as e:
    print(f"Error: {e}")