import subprocess
import shlex

def execute_command(command):
    # Use shlex.split to prevent shell injection
    command_list = shlex.split(command)
    try:
        result = subprocess.run(command_list, check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error: Command failed with return code {e.returncode}\n{e.stderr}"


# Example usage
user_input = "ls -l" # Removed malicious command
output = execute_command(user_input)
print(output)