import re

# Example of a safe regex pattern to prevent ReDoS
def safe_parse(input_string):
    # Use a regex pattern that avoids catastrophic backtracking
    pattern = re.compile(r'^(?:[a-zA-Z0-9_]+)$')  # Simple alphanumeric pattern
    if pattern.match(input_string):
        return True
    else:
        raise ValueError("Input string is not valid.")

# Example usage
try:
    result = safe_parse("valid_input123")
    print("Input is valid:", result)
except ValueError as e:
    print(e)