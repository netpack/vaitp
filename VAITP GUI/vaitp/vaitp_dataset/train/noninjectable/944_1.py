# Vulnerable code example that allows arbitrary code execution
def execute_user_code(user_input):
    # Directly evaluating user input without any restrictions
    try:
        result = eval(user_input)
        return result
    except Exception as e:
        return str(e)

# Example usage
user_input = "__import__('os').system('ls')"  # Malicious input
output = execute_user_code(user_input)
print("Output:", output)