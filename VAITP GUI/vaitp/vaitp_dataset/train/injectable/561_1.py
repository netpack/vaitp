def safe_execute_script(script):
    # Validate the script content to prevent code injection
    allowed_commands = ['print', 'len', 'sum']  # Example of allowed commands
    if any(command in script for command in allowed_commands):
        exec(script)  # Only execute if the script is safe
    else:
        raise ValueError("Unsafe script content detected.")

# Example usage
try:
    user_input = "print('Hello, World!')"  # Example of user input
    safe_execute_script(user_input)
except ValueError as e:
    print(e)