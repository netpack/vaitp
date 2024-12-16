import os

def execute_command(command):
    # Insufficient validation of user-supplied input
    os.system(command)

# Example usage
user_input = input("Enter a command to execute: ")
execute_command(user_input)  # Potentially dangerous if user input is not validated