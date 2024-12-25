import subprocess
import shlex

def shell_quote(arg):
    # Fixed: Uses shlex.quote to escape shell metacharacters
    return shlex.quote(arg)

def execute_command(user_input):
    command = f"echo {shell_quote(user_input)}"
    subprocess.call(command, shell=True)

# Example usage
user_input = "hello; cat /etc/passwd"
execute_command(user_input)