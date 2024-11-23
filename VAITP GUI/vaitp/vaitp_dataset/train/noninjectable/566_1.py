def execute_user_code(user_input):
    # Vulnerable code that directly evaluates user input
    exec(user_input)

# Example usage
user_input = "__import__('os').system('ls')"  # This would be user-provided input
execute_user_code(user_input)