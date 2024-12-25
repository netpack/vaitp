import os
import shlex

def execute_command(name):
    # Sanitized input using shlex.quote
    command = f"echo {shlex.quote(name)}"  # Example command
    os.system(command)

# Example usage
user_input = "user_input; ls"  # Replace with actual user input
execute_command(user_input)