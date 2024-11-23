import subprocess

def execute_command(command):
    # Directly executing user-provided command without validation
    subprocess.run(command, shell=True)

# Example usage
user_input = input("Enter command to execute: ")
execute_command(user_input)