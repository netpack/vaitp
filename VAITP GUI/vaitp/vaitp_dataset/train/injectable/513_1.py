def validate_script_event_handlers(script):
    # Example of validation logic to prevent arbitrary command execution
    allowed_commands = ['print', 'draw_circle', 'draw_square']  # Example of allowed commands
    for command_str in script.split(';'):
        command_str = command_str.strip()
        if not command_str:
            continue  # Skip empty commands
        
        parts = command_str.split('(')
        command = parts[0].strip()
        
        if command not in allowed_commands:
             raise ValueError("Unauthorized command detected: {}".format(command_str))


def execute_script(script):
    try:
        validate_script_event_handlers(script)
        # Instead of using exec, we need a safe way to execute commands
        # We'll just print the script for now, as a placeholder
        print("Executing script (placeholder):", script)
    except ValueError as e:
        print(e)

# Example usage
user_script = "print('Hello, World!'); draw_circle(10)"  # This is allowed
execute_script(user_script)

malicious_script = "os.system('rm -rf /')"  # This is not allowed
execute_script(malicious_script)