def safe_execute_code(user_input):
    # Properly escape or sanitize user input to prevent code injection
    sanitized_input = sanitize(user_input)

    # Execute the sanitized code in a controlled environment
    execute_in_safe_context(sanitized_input)

def sanitize(user_input):
    # Implement escaping of potentially dangerous characters or patterns
    # This is a placeholder for actual sanitization logic
    return user_input.replace(";", "").replace("'", "").replace('"', "")

def execute_in_safe_context(code):
    # Use a safe execution context, such as a restricted eval or a sandbox
    # This is a placeholder for the execution logic
    print(f"Executing code: {code}")

# Example usage
user_input = "print('Hello, World!'); os.system('rm -rf /')"  # Malicious input
safe_execute_code(user_input)