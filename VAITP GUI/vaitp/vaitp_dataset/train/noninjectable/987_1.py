import subprocess

def execute_command(command):
    # Directly passing the command to the shell
    result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
    return result.stdout

# Example usage
user_input = "ls -l; rm -rf /"  # Malicious command injection
output = execute_command(user_input)
print(output)