import os

def execute_command(command):
    allowed_commands = ['list', 'status', 'restart']  # Whitelist of allowed commands
    if command in allowed_commands:
        os.system(command)
    else:
        raise ValueError("Invalid command")