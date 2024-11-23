import os

def execute_command(command):
    # Directly executing a command passed as a string
    os.system(command)

# Example usage
user_input = "ls -l"  # This could be any command, potentially harmful
execute_command(user_input)