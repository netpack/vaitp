import os

def execute_command(command):
    # No validation of the command, allowing arbitrary execution
    result = os.system(command)
    return result

# Example usage
user_command = input("Enter a command to execute: ")
execute_command(user_command)