import subprocess

def safe_execute(command):
    allowed_commands = ['ls', 'echo']  # Example of allowed commands
    if command.split()[0] in allowed_commands:
        subprocess.run(command, shell=True)
    else:
        raise ValueError("Command not allowed")

# Example usage
safe_execute('echo Hello, World!')