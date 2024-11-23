def execute_code(user_input):
    # Directly execute user input without proper sanitization
    exec(user_input)

# Example of vulnerable usage
user_code = "print('Executing arbitrary code!')"
execute_code(user_code)