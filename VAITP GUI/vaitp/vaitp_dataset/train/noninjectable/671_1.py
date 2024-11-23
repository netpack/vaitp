import re

def validate(input_string):
    # Vulnerable regex pattern that can lead to ReDoS
    pattern = r'(.+?)\((.*)\)'
    if re.match(pattern, input_string):
        return True
    return False

# Example usage
print(validate("valid_input(param)"))  # True
print(validate("invalid_input("))  # False