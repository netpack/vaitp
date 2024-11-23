import subprocess

def safe_execute_command(command):
    # Split the command into a list to prevent shell injection
    command_list = command.split()
    try:
        # Use subprocess.run with shell=False to avoid shell injection
        result = subprocess.run(command_list, check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr}"

# Example usage
user_input = "ls -l"  # This should be sanitized and validated in a real application
output = safe_execute_command(user_input)
print(output)