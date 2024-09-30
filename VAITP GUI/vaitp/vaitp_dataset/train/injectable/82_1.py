import ast

def parse_python_code(code):
    try:
        # Use the built-in ast module instead of typed_ast
        return ast.parse(code)
    except SyntaxError as e:
        print(f"Error parsing code: {e}")

# Safe code: parsing Python code with input validation
def sanitize_code(code):
    # Limit the size of the input code to prevent excessive memory allocation
    max_code_size = 1024
    if len(code) > max_code_size:
        raise ValueError("Code is too large")
    return code

user_input_code = "print('Hello, World!')"  # Example user input code
sanitized_code = sanitize_code(user_input_code)

try:
    parse_python_code(sanitized_code)
except Exception as e:
    print(f"Error parsing code: {e}")