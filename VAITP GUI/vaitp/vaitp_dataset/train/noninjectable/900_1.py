def execute_macro(macro_content, context):
    # Directly executing macro content without proper escaping
    return eval(macro_content)

# Example usage
user_input = "__import__('os').system('ls')"  # Arbitrary code input
context = {}  # Context for execution
result = execute_macro(user_input, context)
print(result)