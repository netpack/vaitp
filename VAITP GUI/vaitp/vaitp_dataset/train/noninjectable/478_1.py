import subprocess

def execute_command(command):
    # Vulnerable to command injection
    subprocess.Popen(command, shell=True)

# Example usage
user_input = input("Enter a command to execute: ")
execute_command(user_input)