def safe_macro_execution(user_input):
    # Properly escape user input to prevent code injection
    escaped_input = escape(user_input)
    
    # Execute the macro with the escaped input
    execute_macro(escaped_input)

def escape(input_string):
    # Implement escaping logic here
    # For example, escaping Groovy, Python or Velocity specific characters
    return input_string.replace('$', '\\$').replace('{', '\\{').replace('}', '\\}')

def execute_macro(escaped_input):
    # Code to safely execute the macro with the escaped input
    # This is a placeholder for the actual macro execution logic
    print(f"Executing macro with input: {escaped_input}")

# Example usage
user_input = "<script>alert('XSS')</script>"  # Simulated malicious input
safe_macro_execution(user_input)