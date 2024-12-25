from RestrictedPython import compile_restricted
from RestrictedPython.Guards import full_write_guard

def safe_format_string(format_string, *args, **kwargs):
    # Compile the format string in a restricted environment
    try:
        code = compile_restricted(format_string, '<string>', 'eval')
    except SyntaxError as e:
         return f"Syntax Error: {e}"
    # Execute the code in a restricted environment with guards
    try:
        return eval(code, {'__builtins__': {}}, kwargs)
    except Exception as e:
        return f"Runtime Error: {e}"


# Example usage
try:
    result = safe_format_string("Hello, {user['name']}", user={'name': 'Alice'})
    print(result)
    result2 = safe_format_string("Hello, {name}", name = 'Bob')
    print(result2)
    result3 = safe_format_string("Invalid syntax {")
    print(result3)
    result4 = safe_format_string("Hello, {user.name}", user={'name': 'Alice'})
    print(result4)


except Exception as e:
    print(f"Error: {e}")