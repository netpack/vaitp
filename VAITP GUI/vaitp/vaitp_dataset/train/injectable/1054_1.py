import subprocess
import shlex

def safe_exec(command):
    allowed_commands = ['ls', 'whoami']
    command_parts = shlex.split(command)
    if not command_parts:
        raise ValueError("Empty command provided.")
    if command_parts[0] in allowed_commands:
        result = subprocess.run(command_parts, check=True, text=True, capture_output=True)
        return result.stdout
    else:
        raise ValueError("Unauthorized command execution attempt.")

# Example usage
try:
    print(safe_exec('ls'))
    print(safe_exec('rm -rf /'))
except ValueError as e:
    print(e)