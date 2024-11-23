# Example of code before the fix for CVE-2014-3593, demonstrating eval vulnerability

def execute_user_code(user_input):
    # Directly using eval on user input, which is vulnerable
    try:
        result = eval(user_input)
        return result
    except Exception as e:
        return str(e)

# Example usage
user_input_safe = "2 + 2"  # Safe input
print(execute_user_code(user_input_safe))

user_input_unsafe = "__import__('os').system('ls')"  # Unsafe input
print(execute_user_code(user_input_unsafe))  # This could execute arbitrary code