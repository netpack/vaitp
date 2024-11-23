import os

# Disallow usage of the os module in the sandbox environment
def execute_command(command):
    raise NotImplementedError("Command execution is not allowed in this environment.")

# Example of a function that would have been vulnerable
def vulnerable_function(code):
    # This would execute arbitrary commands if os were allowed
    exec(code)

# Fixed function that prevents arbitrary command execution
def safe_function(code):
    # Only allow a predefined set of operations, no os module access
    allowed_commands = ["print('Hello, World!')"]
    if code in allowed_commands:
        exec(code)
    else:
        raise ValueError("Unauthorized command.")