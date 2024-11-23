def execute_command(command):
    # Dynamically evaluate the command without validation
    return eval(command)

# Example usage
user_input = "os.system('ls')"  # Arbitrary command input
execute_command(user_input)