def execute_user_input(user_input):
    # Vulnerable code that directly evaluates user input
    result = eval(user_input)
    return result

# Example usage
user_input = "__import__('os').system('ls')"  # This input could be provided by an attacker
result = execute_user_input(user_input)
print(result)