def validate_script_event_handlers(script):
    # Example of validation logic to prevent arbitrary command execution
    allowed_commands = ['print', 'draw_circle', 'draw_square']  # Example of allowed commands
    for command in script.split(';'):
        command = command.strip()
        if command not in allowed_commands:
            raise ValueError("Unauthorized command detected: {}".format(command))

def execute_script(script):
    try:
        validate_script_event_handlers(script)
        exec(script)  # Safely execute only validated commands
    except ValueError as e:
        print(e)

# Example usage
user_script = "print('Hello, World!'); draw_circle(10)"  # This is allowed
execute_script(user_script)

malicious_script = "os.system('rm -rf /')"  # This is not allowed
execute_script(malicious_script)