import os
import subprocess

def execute_command(user_input):
    # Using subprocess.run to execute the script with better control
    try:
        subprocess.run(['python', user_input], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
    except FileNotFoundError:
        print(f"Error: Script '{user_input}' not found.")

# Example usage
user_input = input("Enter the script name to execute: ")
execute_command(user_input)