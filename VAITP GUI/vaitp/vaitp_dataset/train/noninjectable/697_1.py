def vulnerable_function(user_input):
    # This function is vulnerable to remote code execution via eval
    result = eval(user_input)  # Dangerous: directly using eval on user input
    return result

# Example usage
user_input = "__import__('os').system('ls')"  # An attacker could inject this
output = vulnerable_function(user_input)