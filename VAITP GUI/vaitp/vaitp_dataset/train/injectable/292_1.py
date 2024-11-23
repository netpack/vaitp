import os
import subprocess

def safe_execute_command(command):
    # Ensure that the command is a list and does not contain any dangerous elements
    if isinstance(command, list) and all(isinstance(arg, str) for arg in command):
        # Use subprocess to execute the command safely
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8')
    else:
        raise ValueError("Invalid command format.")

# Example usage
try:
    output = safe_execute_command(['ls', '-l'])
    print(output)
except Exception as e:
    print(f"Error: {e}")