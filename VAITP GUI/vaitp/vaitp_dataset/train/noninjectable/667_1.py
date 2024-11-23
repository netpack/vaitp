# Vulnerable code that allows arbitrary command execution
import os

def execute_command(command):
    # Directly executing user input without validation
    os.system(command)

# Example usage
user_input = input("Enter a command to execute: ")
execute_command(user_input)  # This can be exploited to run arbitrary commands