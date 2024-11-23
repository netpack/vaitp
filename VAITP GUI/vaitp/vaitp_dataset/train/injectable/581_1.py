import subprocess

def safe_execute(command):
    # Validate the command to ensure it is safe
    allowed_commands = {'ls', 'pwd', 'whoami'}
    if command in allowed_commands:
        return subprocess.run(command, shell=True, check=True)
    else:
        raise ValueError("Unauthorized command execution attempt.")

# Example usage
try:
    safe_execute('ls')  # Safe command
    safe_execute('rm -rf /')  # This will raise an error
except ValueError as e:
    print(e)