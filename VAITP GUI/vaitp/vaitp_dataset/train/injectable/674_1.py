import subprocess

def safe_exec(command):
    # Sanitize the command to prevent arbitrary execution
    allowed_commands = ['ls', 'pwd', 'whoami']  # Example of allowed commands
    if command in allowed_commands:
        result = subprocess.run(command.split(), capture_output=True, text=True)
        return result.stdout
    else:
        raise ValueError("Unauthorized command")

# Example usage
try:
    print(safe_exec('ls'))  # Allowed command
    print(safe_exec('rm -rf /'))  # Unauthorized command
except ValueError as e:
    print(e)