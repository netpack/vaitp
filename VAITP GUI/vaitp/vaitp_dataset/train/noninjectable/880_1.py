import os
import subprocess

# Function that demonstrates the vulnerability by executing a command with unsafe environment variables
def vulnerable_execute(command):
    # Allow manipulation of environment variables
    env = os.environ.copy()  # Copy the current environment variables
    env['PATH'] = '/usr/local/bin:/usr/bin:/bin'  # Potentially unsafe PATH

    # Execute the command with the manipulated environment
    result = subprocess.run(command, shell=True, env=env, capture_output=True, text=True)
    
    return result.stdout, result.stderr

# Example usage
command = "whoami"  # Replace with the command you want to execute
stdout, stderr = vulnerable_execute(command)

print("Output:", stdout)
print("Error:", stderr)