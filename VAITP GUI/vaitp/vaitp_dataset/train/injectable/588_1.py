import subprocess

def safe_execute_command(command):
    # Whitelist of allowed commands
    allowed_commands = ['ls', 'pwd', 'echo']
    command_parts = command.split()

    # Check if the command is in the allowed list
    if command_parts[0] in allowed_commands:
        # Execute the command safely
        result = subprocess.run(command_parts, capture_output=True, text=True)
        return result.stdout
    else:
        raise ValueError("Command not allowed")

# Example usage
try:
    output = safe_execute_command("ls")
    print(output)
except ValueError as e:
    print(e)