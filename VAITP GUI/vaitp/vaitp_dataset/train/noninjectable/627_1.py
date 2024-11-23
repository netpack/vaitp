import os

def execute_command(command):
    # Unsanitized command execution
    os.system(command)

# Example usage
user_input = input("Enter a command to execute: ")
execute_command(user_input)