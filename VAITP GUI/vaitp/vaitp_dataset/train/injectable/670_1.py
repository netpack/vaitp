import subprocess

def safe_execute(command):
    # Use a list to avoid shell injection vulnerabilities
    command_list = command.split()
    result = subprocess.run(command_list, capture_output=True, text=True)
    return result.stdout

# Example of using the safe_execute function
user_input = "ls"  # Replace with user input safely
output = safe_execute(user_input)
print(output)