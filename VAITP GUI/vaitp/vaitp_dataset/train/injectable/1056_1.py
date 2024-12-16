import subprocess

def safe_execute(command):
    # Validate the command to ensure it doesn't allow for arbitrary execution
    allowed_commands = {'ls', 'pwd', 'whoami'}  # Example of allowed commands
    if command in allowed_commands:
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        return result.stdout
    else:
        raise ValueError("Unauthorized command")

# Example usage
try:
    print(safe_execute('ls'))  # This is allowed
    print(safe_execute('rm -rf /'))  # This will raise an error
except ValueError as e:
    print(e)
except subprocess.CalledProcessError as e:
    print(f"Command execution failed: {e}")