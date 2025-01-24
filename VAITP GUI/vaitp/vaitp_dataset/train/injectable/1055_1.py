import subprocess

def secure_execute_command(command):
    # Validate the command to prevent arbitrary execution
    allowed_commands = ['ls', 'whoami', 'pwd']  # Example of allowed commands
    if command not in allowed_commands:
        raise ValueError("Unauthorized command execution attempt.")
    
    # Safely execute the command
    result = subprocess.run([command], shell=False, check=True, text=True, capture_output=True)
    return result.stdout

# Example usage
try:
    print(secure_execute_command('ls'))  # Allowed command
    print(secure_execute_command('rm -rf /'))  # Unauthorized command
except ValueError as e:
    print(e)
except subprocess.CalledProcessError as e:
    print("Command execution failed:", e)