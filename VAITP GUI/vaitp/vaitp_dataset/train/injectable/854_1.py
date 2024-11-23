def secure_execute_script(script):
    # Validate the script to ensure it does not contain malicious commands
    allowed_commands = ["draw_line", "draw_circle", "set_color"]  # Example of allowed commands
    for command in script.split(';'):
        command = command.strip()
        if command.split('(')[0] not in allowed_commands:
            raise ValueError("Unauthorized command detected: " + command)
    
    # Execute the validated script in a controlled environment
    exec(script)

# Example usage
try:
    # This script is safe
    secure_execute_script("draw_line(0, 0, 100, 100); set_color('red');")
    
    # This script would raise an error due to unauthorized command
    secure_execute_script("os.system('rm -rf /')")  # Example of a malicious command
except ValueError as e:
    print(e)