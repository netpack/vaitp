import subprocess

def safe_exec(command):
    # Validate the command to ensure it doesn't allow arbitrary execution
    allowed_commands = ['ls', 'whoami']  # Example of allowed commands
    if command in allowed_commands:
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        return result.stdout
    else:
        raise ValueError("Unauthorized command execution attempt.")

# Example usage
try:
    print(safe_exec('ls'))  # This is allowed
    print(safe_exec('rm -rf /'))  # This would raise an error
except ValueError as e:
    print(e)