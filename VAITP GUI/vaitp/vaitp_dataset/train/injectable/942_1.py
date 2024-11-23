import os
import subprocess

def execute_command(user_input):
    # Validate and sanitize user input to prevent command injection
    if not is_safe_input(user_input):
        raise ValueError("Unsafe input detected!")

    # Use subprocess.run instead of os.system to avoid shell injection
    result = subprocess.run(['python', user_input], capture_output=True, text=True)
    return result.stdout

def is_safe_input(user_input):
    # Implement a whitelist or strict validation for allowed commands
    allowed_commands = {'script1.py', 'script2.py'}
    return user_input in allowed_commands

# Example usage
try:
    user_input = 'script1.py'  # This should be validated
    output = execute_command(user_input)
    print(output)
except ValueError as e:
    print(e)