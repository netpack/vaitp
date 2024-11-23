# Example of a vulnerable code execution that does not sanitize user input

def execute_user_code(user_input):
    # Directly executing user input without any sanitization
    try:
        # This is dangerous as it allows execution of arbitrary code
        exec(user_input)
    except Exception as e:
        print(f"Error executing code: {e}")

# Example of user input that could be malicious
user_input = "__import__('os').system('rm -rf /')"  # Malicious input
execute_user_code(user_input)