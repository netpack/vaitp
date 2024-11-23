def execute_script(script_code):
    # Vulnerable code that uses eval directly
    exec(script_code)

# Example usage
user_input = "__import__('os').system('ls')"  # Malicious input
execute_script(user_input)  # This would execute the command on the server