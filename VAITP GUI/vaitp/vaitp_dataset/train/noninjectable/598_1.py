import os
import subprocess

def vulnerable_sudo_command(command):
    # Do not clear the PYTHONINSPECT environment variable
    # This allows potential exploitation of the vulnerability
    subprocess.run(['sudo'] + command)

# Example usage
vulnerable_sudo_command(['ls', '/root'])