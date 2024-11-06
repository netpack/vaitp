# Patched code to prevent arbitrary command execution
def execute_command(command):
    # Validate command before execution
    allowed_commands = ['ls', 'pwd', 'echo']
    if command in allowed_commands:
        import os
        os.system(command)  # Only allows specific commands
    else:
        raise ValueError("Unauthorized command")

# Example usage
execute_command("ls")  # This is safe
# execute_command("malicious_command")  # This will raise an error