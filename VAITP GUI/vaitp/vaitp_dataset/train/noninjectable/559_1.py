import os

# This function demonstrates the vulnerability by allowing execution of arbitrary OS commands
def execute_command(command):
    # Directly executing the command without restriction
    return os.system(command)

# Example usage
# This could allow an attacker to execute arbitrary commands
result = execute_command("ls")  # Potentially harmful command
print(result)