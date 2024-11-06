import os

def execute_command(command):
    os.system(command)  # Vulnerable to command injection