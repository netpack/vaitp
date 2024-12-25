import subprocess
import shlex

def process_metadata(metadata):
    # Assume metadata is untrusted input
    command = metadata.get("command")
    
    # Vulnerable to command injection
    if command:
        try:
            command_list = shlex.split(command)
            output = subprocess.check_output(command_list)
            return output
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            return f"Error executing command: {e}"
    return "No command provided."