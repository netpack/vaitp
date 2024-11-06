# Vulnerable code with a backdoor
def execute_command(command):
    import os
    os.system(command)  # This allows arbitrary command execution

# Example usage
execute_command("malicious_command")