import ast

def safe_eval(expression):
    try:
        # Use ast.literal_eval for safe evaluation of mathematical expressions
        result = ast.literal_eval(expression)
        return result
    except (SyntaxError, ValueError):
        return None

user_input = input("Enter a mathematical expression: ")
result = safe_eval(user_input)

if result is not None:
    print("Result:", result)
else:
    print("Invalid input. Please enter a valid mathematical expression.")

