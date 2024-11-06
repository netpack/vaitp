def evaluate_expression(user_input):
    # Vulnerable code: executing user input directly
    result = eval(user_input)
    return result

# Example usage
user_input = "1 + 2; os.system('cat /etc/passwd')"  # User input that could execute arbitrary commands
output = evaluate_expression(user_input)