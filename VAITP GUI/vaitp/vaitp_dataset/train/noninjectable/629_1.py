# Example of vulnerable code that allows arbitrary code execution

def execute_user_code(code):
    # Directly executing user-provided code without any restrictions
    exec(code)

# Example usage
user_code = "__import__('os').system('whoami')"  # This is user-provided code
execute_user_code(user_code)