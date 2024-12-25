import os
import subprocess

# Function to securely execute a command without allowing environment variable manipulation
def secure_execute(command):
    # Clear any potentially dangerous environment variables
    safe_env = {
        'PATH': '/usr/bin:/bin',  # Set a safe PATH
        'HOME': os.path.expanduser('~'),  # Set HOME to the user's home directory
    }
    
    # Execute the command with the safe environment
    result = subprocess.run(command, shell=False, env=safe_env, capture_output=True, text=True)
    
    return result.stdout, result.stderr

# Example usage
command = ["whoami"]  # Replace with the command you want to execute
stdout, stderr = secure_execute(command)

print("Output:", stdout)
print("Error:", stderr)