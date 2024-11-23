import re

def safe_execute(command):
    # Only allow specific commands or patterns
    allowed_commands = ['command1', 'command2', 'command3']
    if command in allowed_commands:
        # Execute the command safely
        return execute_command(command)
    else:
        raise ValueError("Unauthorized command execution attempt.")

def execute_command(command):
    # Placeholder for actual command execution logic
    return f"Executing: {command}"

# Example of how the API might call the safe_execute function
def api_call(command):
    try:
        result = safe_execute(command)
        return {"status": "success", "result": result}
    except ValueError as e:
        return {"status": "error", "message": str(e)}

# Example usage
response = api_call('command1')  # Allowed command
print(response)

response = api_call('unauthorized_command')  # Not allowed command
print(response)