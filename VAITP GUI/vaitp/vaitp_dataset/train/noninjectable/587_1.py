import subprocess

# Vulnerable function that allows arbitrary command execution
def execute_command(command):
    # No restrictions on the command input
    result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
    return result.stdout

# Example usage
try:
    output = execute_command('ls')  # Arbitrary command
    print(output)
    
    output = execute_command('rm -rf /')  # Dangerous command, could be executed
    print(output)
except Exception as e:
    print(e)