from RestrictedPython import compile_restricted
from RestrictedPython.Guards import full_write_guard

def safe_format_string(format_string, *args, **kwargs):
    # Compile the format string in a restricted environment
    code = compile_restricted(format_string, '<string>', 'eval')
    # Execute the code in a restricted environment with guards
    return eval(code, {'__builtins__': {}})

# Example usage
try:
    result = safe_format_string("Hello, {user.name}", user={'name': 'Alice'})
    print(result)
except Exception as e:
    print(f"Error: {e}")