def execute_user_code(user_input):
    # Directly executing user input without any sanitization or escaping
    exec(user_input)

# Example of potentially malicious user input
user_input = "__import__('os').system('rm -rf /')"  # Malicious command
execute_user_code(user_input)