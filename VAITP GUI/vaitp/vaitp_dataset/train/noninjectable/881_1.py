def execute_macro(user_input):
    # Vulnerable code that executes user input directly without escaping
    eval(user_input)

# Example usage
user_input = "print('This is a malicious command!')"  # Simulated malicious input
execute_macro(user_input)