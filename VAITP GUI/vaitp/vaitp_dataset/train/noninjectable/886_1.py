def execute_user_code(user_input):
    # Vulnerable code that directly evaluates user input
    eval(user_input)

# Example usage
user_input = "__import__('os').system('ls')"  # Simulated user input that can execute arbitrary code
execute_user_code(user_input)