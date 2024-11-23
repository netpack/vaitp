import subprocess
import shlex

def safe_execute(command):
    # Validate the command to prevent arbitrary command execution
    allowed_commands = ['command1', 'command2', 'command3']  # Define allowed commands
    command_parts = shlex.split(command)
    
    if command_parts[0] in allowed_commands:
        # Execute the command safely
        subprocess.run(command_parts)
    else:
        raise ValueError("Unauthorized command execution attempt detected.")

# Example usage
try:
    user_input = "command1"  # This should be sanitized and validated
    safe_execute(user_input)
except ValueError as e:
    print(e)