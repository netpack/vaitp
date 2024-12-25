import subprocess

def safe_execute(command):
    # Ensure that only allowed commands are executed
    allowed_commands = ['ls', 'pwd', 'whoami']  # Example of allowed commands
    if command in allowed_commands:
        result = subprocess.run([command], capture_output=True, text=True)
        return result.stdout
    else:
        raise ValueError("Command not allowed")

# Example usage
try:
    print(safe_execute('ls'))  # This is allowed
    print(safe_execute('bash'))  # This would raise an error
except ValueError as e:
    print(e)