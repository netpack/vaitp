import re

def safe_execute(user_input):
    # Sanitize input to prevent eval injection
    sanitized_input = re.sub(r'[^a-zA-Z0-9_]', '', user_input)
    
    # Only allow a predefined set of commands or functions
    allowed_commands = ['function1', 'function2']
    if sanitized_input in allowed_commands:
        # Execute the safe command
        return execute_command(sanitized_input)
    else:
        raise ValueError("Invalid command")

def execute_command(command):
    # Placeholder for command execution logic
    return f"Executing {command}"

# Example usage
try:
    user_input = "function1"  # Simulated user input
    result = safe_execute(user_input)
    print(result)
except ValueError as e:
    print(e)