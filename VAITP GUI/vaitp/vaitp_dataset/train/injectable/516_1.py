import subprocess
import shlex

def safe_execute(command):
    # Only allow specific commands to be executed
    allowed_commands = ['ls', 'whoami']  # Define allowed commands
    if command in allowed_commands:
        result = subprocess.run(shlex.split(command), capture_output=True, text=True)
        return result.stdout
    else:
        raise ValueError("Command not allowed!")

# Example usage
try:
    print(safe_execute('ls'))  # Allowed command
    print(safe_execute('rm -rf /'))  # Not allowed, will raise an error
except ValueError as e:
    print(e)