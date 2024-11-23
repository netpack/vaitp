def execute_command(command):
    # Insufficient sanitization of user input
    import os
    os.system(command)

# Example usage
user_input = input("Enter a command to execute: ")
execute_command(user_input)  # Vulnerable to arbitrary command execution