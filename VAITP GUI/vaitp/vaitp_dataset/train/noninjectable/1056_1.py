import os

def execute_command(command):
    # Insufficient validation of user input
    os.system(command)

# Example of potentially dangerous input
user_input = "ls; rm -rf /"  # An attacker could inject harmful commands
execute_command(user_input)