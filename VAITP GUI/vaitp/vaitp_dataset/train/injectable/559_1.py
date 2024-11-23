import vim

# This function is an example of how to restrict access to OS commands
def secure_eval(command):
    # Prevent execution of arbitrary OS commands
    if 'os.system' in command or 'subprocess' in command:
        raise Exception("Execution of OS commands is not allowed in restricted mode.")
    return eval(command)

# Example usage
try:
    # Attempt to execute a command that could be harmful
    result = secure_eval("os.system('ls')")
except Exception as e:
    print(e)  # Output: Execution of OS commands is not allowed in restricted mode.