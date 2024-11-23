# Vulnerable code that could allow arbitrary code execution
import subprocess

def execute_command(command):
    # This function executes a command passed to it, which is a security risk
    subprocess.run(command, shell=True)

# Example usage
user_input = "some_input"  # This could be manipulated by an attacker
execute_command(user_input)