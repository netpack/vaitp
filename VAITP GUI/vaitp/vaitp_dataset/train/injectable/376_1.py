import subprocess
import shlex  # Safe way to handle shell arguments

def shell_quote(arg):
    # Patched: uses shlex.quote to safely escape the argument
    return shlex.quote(arg)

def execute_command(user_input):
    command = f"echo {shell_quote(user_input)}"
    subprocess.call(command, shell=True)

# Example usage
user_input = "hello; cat /etc/passwd"  # Malicious input
execute_command(user_input)