import subprocess

def process_metadata(metadata):
    # Assume metadata is untrusted input
    command = metadata.get("command")
    
    # Vulnerable to command injection
    if command:
        output = subprocess.check_output(command, shell=True)
        return output
    return "No command provided."