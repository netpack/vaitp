import subprocess
import shlex

def execute_command(command):
    # Split the command into a list of arguments using shlex.split for better security
    try:
        command_list = shlex.split(command)
    except ValueError:
        print("Invalid command syntax.")
        return
    # Execute the command with the list of arguments. shell=False is the default and safer.
    try:
        subprocess.run(command_list, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e}")
    except FileNotFoundError:
        print("Command not found.")

# Example usage
user_input = input("Enter command to execute: ")
execute_command(user_input)