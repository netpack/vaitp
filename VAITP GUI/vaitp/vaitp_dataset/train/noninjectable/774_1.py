import subprocess

def execute_command(command):
    # Insufficient sanitization of user input
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

# Example usage
user_input = input("Enter a command to execute: ")
print(execute_command(user_input))  # Vulnerable to arbitrary command execution