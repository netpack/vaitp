import subprocess

def execute_command(command):
    # Directly executing user-supplied command without validation
    result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
    return result.stdout

# Example usage
user_input = input("Enter a command: ")  # Simulating user input
output = execute_command(user_input)
print(output)