import os
import subprocess

def secure_sudo_command(command):
    # Clear the PYTHONINSPECT environment variable to mitigate CVE-2006-0151
    env = os.environ.copy()
    env.pop('PYTHONINSPECT', None)
    
    # Execute the command with sudo
    subprocess.run(['sudo'] + command, env=env)

# Example usage
secure_sudo_command(['ls', '/root'])