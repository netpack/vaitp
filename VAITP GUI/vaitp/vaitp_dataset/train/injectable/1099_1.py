import re

def safe_eval(expression):
    # Only allow numbers and basic arithmetic operators
    if re.match(r'^[0-9+\-*/().\s]+$', expression):
        return eval(expression)
    else:
        raise ValueError("Invalid expression")

# Example usage in the /math command
def math_command(expression):
    try:
        result = safe_eval(expression)
        return result
    except Exception as e:
        return str(e)