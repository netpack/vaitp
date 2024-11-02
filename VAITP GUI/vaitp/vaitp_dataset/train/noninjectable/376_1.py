import subprocess

def shell_quote(arg):
    # Vulnerable: does not escape shell metacharacters
    return arg

def execute_command(user_input):
    command = f"echo {shell_quote(user_input)}"
    subprocess.call(command, shell=True)

# Example usage
user_input = "hello; cat /etc/passwd"  # Malicious input
execute_command(user_input)