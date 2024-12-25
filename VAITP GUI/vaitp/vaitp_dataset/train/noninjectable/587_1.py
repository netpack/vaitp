import subprocess

# Vulnerable function that allows arbitrary command execution
def execute_command(command):
    # No restrictions on the command input
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error: Command '{command}' failed with return code {e.returncode}. Output:\n{e.stderr}"


# Example usage
try:
    output = execute_command('ls')  # Arbitrary command
    print(output)
    
    output = execute_command('rm -rf /')  # Dangerous command, could be executed
    print(output)
except Exception as e:
    print(e)