import re
import subprocess

def sanitize_input(username):
    # Sanitize the username to prevent malicious characters
    if re.search(r'[^a-zA-Z0-9_\-]', username):
        raise ValueError("Invalid username: contains malicious characters.")
    return username

def login(username):
    # Sanitize the username before using it
    sanitized_username = sanitize_input(username)

    # Properly quote the variables to prevent command injection
    command = ["wrongpass", sanitized_username]
    
    # Execute the command safely (using subprocess, for example)
    result = subprocess.run(command, capture_output=True, text=True)

    # Check the result of the command execution
    if result.returncode == 0:
        print("Login successful.")
    else:
        print("Login failed.")

# Example usage
try:
    login('- a')  # This input should be sanitized and rejected
except ValueError as e:
    print(e)