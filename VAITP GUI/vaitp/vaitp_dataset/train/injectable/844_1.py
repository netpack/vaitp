import os

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
    # DO NOT USE eval() in any production system or where user input can be interpreted
    # If you need a more robust execution context consider using a sandbox (e.g. with docker, or a dedicated library like pyMiniRacer)

    print(f"Executing code: {code}")
    # Example of a basic safe execution, but still VERY risky
    try:
        exec(code) # VERY UNSAFE
    except Exception as e:
        print(f"Error executing code: {e}")


# Example usage
user_input = "print('Hello, World!'); os.system('rm -rf /')"  # Malicious input
safe_execute_code(user_input)

user_input2 = "print(1+2)"
safe_execute_code(user_input2)