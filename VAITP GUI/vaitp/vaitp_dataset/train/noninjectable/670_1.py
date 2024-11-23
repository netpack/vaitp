import subprocess

def execute_command(command):
    # Directly using user input in a shell command, which is vulnerable to injection
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

# Example of using the execute_command function
user_input = "ls; rm -rf /"  # Example of malicious input
output = execute_command(user_input)
print(output)