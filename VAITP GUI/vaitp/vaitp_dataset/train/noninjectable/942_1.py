import os

def execute_command(user_input):
    # Directly executing user input without validation
    os.system(f'python {user_input}')

# Example usage
user_input = input("Enter the script name to execute: ")
execute_command(user_input)