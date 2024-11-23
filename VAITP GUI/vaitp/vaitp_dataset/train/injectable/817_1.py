def safe_execute_code(user_input):
    # Properly escape or sanitize the user input to prevent code injection
    sanitized_input = sanitize(user_input)
    
    # Execute the sanitized code in a controlled environment
    try:
        exec(sanitized_input, {"__builtins__": {}})
    except Exception as e:
        print(f"Error executing code: {e}")

def sanitize(input_code):
    # Implement sanitization logic to remove or escape dangerous constructs
    # For example, you might want to restrict certain keywords or patterns
    forbidden_keywords = ['import', 'exec', 'eval', '__']
    for keyword in forbidden_keywords:
        if keyword in input_code:
            raise ValueError(f"Forbidden keyword detected: {keyword}")
    return input_code  # Return sanitized input