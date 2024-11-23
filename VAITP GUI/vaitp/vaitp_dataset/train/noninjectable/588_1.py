import subprocess

def execute_command(command):
    # Directly executing the command without validation
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

# Example usage
user_input = "ls; rm -rf /"  # Example of malicious input
output = execute_command(user_input)
print(output)