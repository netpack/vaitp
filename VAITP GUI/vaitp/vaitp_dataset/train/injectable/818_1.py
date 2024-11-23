def safe_execute_code(user_input):
    # Properly escape user input to prevent code injection
    sanitized_input = escape_user_input(user_input)
    
    # Use a safe execution context (e.g., a restricted environment)
    exec_context = {}
    
    try:
        # Execute the sanitized code in a controlled environment
        exec(sanitized_input, exec_context)
    except Exception as e:
        # Handle exceptions gracefully
        print(f"Error executing code: {e}")

def escape_user_input(input_code):
    # Implement escaping logic to prevent execution of arbitrary code
    # For simplicity, this function just removes potentially dangerous characters
    dangerous_chars = [';', 'import', 'exec', 'eval', '__', 'os', 'sys']
    for char in dangerous_chars:
        input_code = input_code.replace(char, '')
    return input_code

# Example of usage
user_code = "print('Hello, World!')"
safe_execute_code(user_code)