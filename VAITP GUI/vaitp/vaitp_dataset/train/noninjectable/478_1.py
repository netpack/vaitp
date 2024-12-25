import subprocess
import shlex

def execute_command(command):
    # Fixed: Use shlex.split() to properly handle spaces and special characters
    command_list = shlex.split(command)
    subprocess.Popen(command_list)

# Example usage
user_input = input("Enter a command to execute: ")
execute_command(user_input)