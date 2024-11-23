import os

def execute_command(command):
    # No input validation, allowing arbitrary command execution
    os.system(command)

# Example usage
user_input = input("Enter a command to execute: ")
execute_command(user_input)