import subprocess

def execute_command(command):
    # Vulnerable code that allows arbitrary command execution
    subprocess.run(command, shell=True)

# Example usage
execute_command('ls; rm -rf /')  # This could be exploited