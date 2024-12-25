import shlex
import subprocess

def safe_execute_command(name):
    # Sanitize the input using shlex.quote to prevent shell injection
    safe_name = shlex.quote(name)
    command = ["echo", safe_name]  # Example command
    subprocess.run(command, check=True)

# Example usage
user_input = "user_input"  # Replace with actual user input
safe_execute_command(user_input)