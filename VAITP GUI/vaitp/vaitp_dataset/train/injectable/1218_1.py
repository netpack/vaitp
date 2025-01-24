import subprocess
import shlex

def safe_execute(command):
    # Validate the command to prevent injection
    allowed_commands = ['ls', 'date', 'whoami']  # Example of allowed commands
    if command in allowed_commands:
        result = subprocess.run([command], check=True, capture_output=True, text=True)
        return result.stdout
    else:
        raise ValueError("Invalid command")

# Example usage
try:
    user_input = 'ls'  # Simulating user input
    output = safe_execute(user_input)
    print(output)
except ValueError as e:
    print(e)