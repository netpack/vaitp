# Vulnerable code that could represent the backdoor

import os

def execute_command(command):
    os.system(command)

if __name__ == "__main__":
    # This could be exploited to execute arbitrary commands
    user_input = input("Enter a command to execute: ")
    execute_command(user_input)