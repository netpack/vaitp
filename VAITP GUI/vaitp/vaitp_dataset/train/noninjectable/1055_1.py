# Vulnerable code example demonstrating insufficient validation of user input

def execute_command(command):
    # Directly executing user-supplied command without validation
    result = os.system(command)
    return result

# Example usage
user_input = input("Enter a command to execute: ")
execute_command(user_input)  # Vulnerable to arbitrary command execution