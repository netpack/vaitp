import subprocess
import shlex

def execute_command(command):
    # Split the command into a list of arguments using shlex
    command_list = shlex.split(command)
    
    # Execute the command using subprocess.run with a list of arguments
    # shell=False to avoid shell injection vulnerabilities
    result = subprocess.run(command_list, capture_output=True, text=True, check=False)
    return result.stdout

# Example usage
user_input = "ls; rm -rf /"  # Example of malicious input
output = execute_command(user_input)
print(output)