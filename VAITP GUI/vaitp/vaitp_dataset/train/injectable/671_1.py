import re

def validate(input_string):
    # Fixed the regex to avoid catastrophic backtracking
    pattern = r'^[^\(\)]+(\([^\(\)]+\))?$'
    if re.match(pattern, input_string):
        return True
    return False

# Example usage
print(validate("valid_input"))  # True
print(validate("valid_input(param)"))  # True
print(validate("invalid_input("))  # False