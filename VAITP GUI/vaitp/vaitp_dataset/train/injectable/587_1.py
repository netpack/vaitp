import subprocess

# Fixed function to execute a command securely
def secure_execute(command):
    # Only allow specific commands to be executed
    allowed_commands = ['ls', 'whoami', 'pwd']
    
    if command in allowed_commands:
        result = subprocess.run([command], check=True, capture_output=True, text=True)
        return result.stdout
    else:
        raise PermissionError("This command is not allowed.")

# Example usage
try:
    output = secure_execute('ls')  # Allowed command
    print(output)
    
    output = secure_execute('rm -rf /')  # Not allowed command, will raise an error
    print(output)
except PermissionError as e:
    print(e)