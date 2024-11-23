# Example of a fix for CVE-2023-29522
# This code snippet demonstrates how to sanitize user input to prevent remote code execution.

def sanitize_input(user_input):
    # Disallow certain characters or patterns that could lead to code execution
    forbidden_patterns = ['$', '{', '}', '(', ')', 'import', 'exec', 'eval']
    for pattern in forbidden_patterns:
        if pattern in user_input:
            raise ValueError("Invalid input detected!")

    return user_input

def execute_macro(user_input):
    # Sanitize the input before processing
    sanitized_input = sanitize_input(user_input)

    # Proceed with executing the macro safely
    # (This is a placeholder for the actual macro execution logic)
    print(f"Executing macro with sanitized input: {sanitized_input}")

# Example usage
try:
    user_input = "some_safe_macro_input"  # Example of user input
    execute_macro(user_input)
except ValueError as e:
    print(e)