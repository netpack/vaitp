import os

def execute_command(user_input):
    # Vulnerable to command injection
    command = "echo " + user_input  # This could be any command
    os.system(command)

# Example usage
user_input = "cat /etc/passwd"  # Malicious input
execute_command(user_input)